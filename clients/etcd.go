package base

import (
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc"
	"time"
)

type ETCDConf struct {
	Endpoints []string `yaml:"endpoints" json:"endpoints"` // 服务地址列表
	Username  string   `yaml:"username" json:"username"`   // 用户名
	Password  string   `yaml:"password" json:"password"`   // 密码
}

// InitETCDClient 初始化etcd client，
func InitETCDClient(conf ETCDConf) (*clientv3.Client, error) {
	etcdConf := clientv3.Config{
		Endpoints:            conf.Endpoints,   // 地址列表
		AutoSyncInterval:     time.Minute,      // 若etcd出现扩缩容，间隔1分钟自动获取最新成员列表
		DialTimeout:          5 * time.Second,  // 拨号超时时间
		DialKeepAliveTime:    10 * time.Second, // 心跳间隔时间
		DialKeepAliveTimeout: 3 * time.Second,  // 心跳超时时间
		PermitWithoutStream:  true,             // 不存在活跃的stream时仍然上报心跳，目前etcd主要用于选主、配置，存在较大的空闲时间
		Username:             conf.Username,    // 用户名
		Password:             conf.Password,    // 密码
		DialOptions:          []grpc.DialOption{grpc.WithBlock()},
	}
	return clientv3.New(etcdConf)
}
