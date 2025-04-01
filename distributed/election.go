package distributed

import (
	"context"
	"errors"
	"fmt"
	"github.com/haysons/pkg/log"
	"github.com/haysons/pkg/utils"
	"github.com/rs/xid"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
	"sync"
	"sync/atomic"
	"time"
)

type Election struct {
	id        string // 竞选者id，当前使用ip-uid作为唯一标识
	isLeader  int32
	electCh   chan error
	readyCh   chan struct{}
	readyOnce sync.Once
	ctx       context.Context
	cancel    context.CancelFunc
	session   *concurrency.Session
	election  *concurrency.Election
}

// NewElection 新建选举对象
func NewElection(client *clientv3.Client, elKey, elID string) (*Election, error) {
	if elKey == "" {
		return nil, errors.New("empty election key")
	}
	// 若没有主动指定
	if elID == "" {
		elID = fmt.Sprintf("%s-%s", utils.GetLocalIP(), xid.New().String())
	}
	session, err := concurrency.NewSession(client, concurrency.WithTTL(5))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Election{
		id:       elID,
		isLeader: 0,
		electCh:  make(chan error, 3),
		readyCh:  make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
		session:  session,
		election: concurrency.NewElection(session, elKey),
	}, nil
}

// ID 当前竞选者的id
func (el *Election) ID() string {
	return el.id
}

// IsLeader 当前竞选者是否为leader
func (el *Election) IsLeader() bool {
	return atomic.LoadInt32(&el.isLeader) == 1
}

// Start 发起竞选，并等待出现leader，若等待时间过长将会返回错误
func (el *Election) Start(ctx context.Context) error {
	go el.run(ctx)
	return el.waitForReady()
}

// run 发起竞选，并监听leader变化，此方法会一直阻塞，直到调用close方法
func (el *Election) run(ctx context.Context) {
	// 立即发起竞选
	el.elect()
	leaderChange := el.election.Observe(el.ctx)
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-el.electCh:
			if err != nil {
				log.Err(err).Str("module", "election").Str("id", el.id).Msg("election failed")
				time.Sleep(time.Second)
				el.elect()
			} else {
				log.Info().Str("module", "election").Str("id", el.id).Msg("elect leader success")
			}
		case resp, ok := <-leaderChange:
			if !ok {
				return
			}
			if len(resp.Kvs) > 0 {
				curLeader := string(resp.Kvs[0].Value)
				el.setLeader(ctx, curLeader)
				log.Info().Str("module", "election").Str("id", el.id).Str("current leader", curLeader).Msg("leader changed")
				el.readyOnce.Do(func() {
					// 首次监听到leader发生变化，则初始化完成
					close(el.readyCh)
				})
			}
		case <-ticker.C:
			// 此处为兜底逻辑，若监听leader变化的管道发生网络问题，可通过定期的查询判断出leader是否发生变化
			resp, err := el.election.Leader(el.ctx)
			if err != nil {
				log.Err(err).Str("module", "election").Str("id", el.id).Msg("query leader failed")
				if errors.Is(err, concurrency.ErrElectionNoLeader) {
					el.elect()
				}
				continue
			}
			if resp != nil && len(resp.Kvs) > 0 {
				el.setLeader(ctx, string(resp.Kvs[0].Value))
			}
		case <-el.ctx.Done():
			return
		}
	}
}

func (el *Election) setLeader(_ context.Context, curLeader string) {
	if el.id == curLeader {
		atomic.CompareAndSwapInt32(&el.isLeader, 0, 1)
	} else {
		atomic.CompareAndSwapInt32(&el.isLeader, 1, 0)
	}
}

// elect 发起竞选
func (el *Election) elect() {
	go func() {
		err := el.election.Campaign(el.ctx, el.id)
		el.electCh <- err
	}()
}

// waitForReady 实际等待
func (el *Election) waitForReady() error {
	ctx, cancel := context.WithTimeout(el.ctx, 10*time.Second)
	defer cancel()
	select {
	case <-el.readyCh:
		return nil
	case <-ctx.Done():
		if err := el.Close(); err != nil {
			return err
		}
		return errors.New("wait for election ready timeout")
	}
}

// Close 关闭竞选，清理资源，让leader立刻结束任期，需在程序退出时调用，否则间隔5s才能重新选出leader
func (el *Election) Close() error {
	el.cancel()
	return el.session.Close()
}
