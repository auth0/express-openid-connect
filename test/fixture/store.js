import { promisify } from 'util';
import redis from 'redis-mock';
import connectRedis from 'connect-redis';

const RedisStore = connectRedis({ Store: class Store {} });

export default () => {
  const client = redis.createClient();
  const store = new RedisStore({ client: client, prefix: '' });
  client.asyncSet = promisify(client.set).bind(client);
  const get = promisify(client.get).bind(client);
  client.asyncGet = async (id) => {
    const val = await get(id);
    return val ? JSON.parse(val) : val;
  };
  client.asyncDbsize = promisify(client.dbsize).bind(client);
  client.asyncTtl = promisify(client.ttl).bind(client);
  return { client, store };
};
