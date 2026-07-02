using System.Threading.Channels;

namespace HostsGuard.Service;

/// <summary>
/// In-process broadcast bus bridging the engines (ETW DNS, connections, engine
/// events) to the gRPC streaming RPCs. Each subscriber gets its own bounded
/// channel; slow consumers drop oldest instead of stalling the publisher.
/// </summary>
public sealed class EventBus
{
    private readonly object _gate = new();
    private readonly Dictionary<Type, List<object>> _subscribers = new();

    public Subscription<T> Subscribe<T>()
    {
        var channel = Channel.CreateBounded<T>(new BoundedChannelOptions(1024)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
        });

        lock (_gate)
        {
            if (!_subscribers.TryGetValue(typeof(T), out var list))
            {
                list = new List<object>();
                _subscribers[typeof(T)] = list;
            }

            list.Add(channel);
        }

        return new Subscription<T>(this, channel);
    }

    public void Publish<T>(T item)
    {
        List<object>? list;
        lock (_gate)
        {
            if (!_subscribers.TryGetValue(typeof(T), out list))
            {
                return;
            }

            list = new List<object>(list);
        }

        foreach (var sub in list)
        {
            ((Channel<T>)sub).Writer.TryWrite(item);
        }
    }

    private void Unsubscribe<T>(Channel<T> channel)
    {
        lock (_gate)
        {
            if (_subscribers.TryGetValue(typeof(T), out var list))
            {
                list.Remove(channel);
            }
        }

        channel.Writer.TryComplete();
    }

    public sealed class Subscription<T> : IDisposable
    {
        private readonly EventBus _bus;
        private readonly Channel<T> _channel;

        internal Subscription(EventBus bus, Channel<T> channel)
        {
            _bus = bus;
            _channel = channel;
        }

        public ChannelReader<T> Reader => _channel.Reader;

        public void Dispose() => _bus.Unsubscribe(_channel);
    }
}
