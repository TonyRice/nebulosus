package io.nebulosus.persistence;

import com.hazelcast.core.IMap;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Logger;
import io.jsync.app.core.service.ClusterService;

/**
 * This service simply ensure's that Hazelcast loads the data into the cluster.
 */
public class NBDataPreloadService implements ClusterService {
    private boolean started = false;

    @Override
    public void start(Cluster owner) {
        started = true;

        Logger logger = owner.logger();

        logger.info("Ensuring the map \"nbdata\" can be preloaded.");

        // This represents the data we store in this nebulosus keyvalue store
        IMap<String, String> nbdata = owner.data().getMap("nbdata",false);

        logger.info("Finished loading the map \"nbdata\" with " + nbdata.size() + " keys.");

    }

    @Override
    public void stop() {

    }

    @Override
    public boolean running() {
        return started;
    }

    @Override
    public String name() {
        return "PreLoadService";
    }
}