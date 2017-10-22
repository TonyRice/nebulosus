package io.nebulosus.persistence;

import com.hazelcast.core.HazelcastInstance;
import io.jsync.app.core.persistence.DataPersistor;

import java.util.Collection;
import java.util.Map;
import java.util.Properties;

/**
 * This is not really used. It only exist to fill some empty spaces and ease some minds.
 */
public class DummyDataPersistor implements DataPersistor {
    @Override
    public void init(HazelcastInstance hazelcastInstance, Properties properties, String s) {
        System.err.println("Data persistence not currently supported.");
        // This shouldn't ever be spawned. We do not utilize jsync.io or Hazelcast for persistence
        System.exit(1);
    }

    @Override
    public void destroy() {

    }

    @Override
    public void store(Object o, Object o2) {

    }

    @Override
    public void storeAll(Map map) {

    }

    @Override
    public void delete(Object o) {

    }

    @Override
    public void deleteAll(Collection collection) {

    }

    @Override
    public Object load(Object o) {
        return null;
    }

    @Override
    public Map loadAll(Collection collection) {
        return null;
    }

    @Override
    public Iterable loadAllKeys() {
        return null;
    }
}
