package extism

import (
	"context"
	"errors"
	"time"

	"sync"
)

type PluginFunc = func(ctx context.Context) (*Plugin, error)

type pluginInstance struct {
	lock   sync.Mutex
	Plugin *Plugin
}

func (p *pluginInstance) Done() {
	p.lock.Unlock()
}

type Pool struct {
	maxInstances int
	plugins      map[string]PluginFunc
	instances    map[string][]*pluginInstance
	lock         sync.Mutex
}

func NewPool(maxInstances int) *Pool {
	return &Pool{
		maxInstances: maxInstances,
		plugins:      map[string]PluginFunc{},
		instances:    map[string][]*pluginInstance{},
	}
}

func (pool *Pool) Add(key string, f PluginFunc) {
	pool.lock.Lock()
	defer pool.lock.Unlock()
	pool.plugins[key] = f
	pool.instances[key] = []*pluginInstance{}
}

func (pool *Pool) Count(key string) int {
	pool.lock.Lock()
	defer pool.lock.Unlock()
	x, ok := pool.instances[key]
	if !ok {
		return 0
	}

	return len(x)
}

func (pool *Pool) findAvailable(key string) *pluginInstance {
	for _, p := range pool.instances[key] {
		if p.lock.TryLock() {
			return p
		}
	}

	return nil
}

func (pool *Pool) Get(ctx context.Context, key string, timeout time.Duration) (*pluginInstance, error) {
	end := time.After(timeout)
	pool.lock.Lock()
	defer pool.lock.Unlock()

	if p := pool.findAvailable(key); p != nil {
		return p, nil
	}

	if len(pool.instances[key]) < pool.maxInstances {
		f := pool.plugins[key]
		plugin, err := f(ctx)
		if err != nil {
			return nil, err
		}
		instance := &pluginInstance{Plugin: plugin}
		instance.lock.Lock()
		pool.instances[key] = append(pool.instances[key], instance)
		return instance, err
	}

	for {
		select {
		case <-end:
			return nil, errors.New("Timed out getting instance for key: " + key)
		default:
			p := pool.findAvailable(key)
			if p != nil {
				return p, nil
			}
		}
	}
}

func (pool *Pool) WithPlugin(ctx context.Context, key string, timeout time.Duration, f func(*Plugin) error) error {
	p, err := pool.Get(ctx, key, timeout)
	if err != nil {
		return err
	}
	defer p.Done()
	return f(p.Plugin)
}
