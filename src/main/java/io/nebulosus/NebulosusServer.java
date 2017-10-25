package io.nebulosus;

import com.hazelcast.config.EvictionPolicy;
import com.hazelcast.config.InMemoryFormat;
import com.hazelcast.config.MapConfig;
import com.hazelcast.config.MapStoreConfig;
import com.hazelcast.core.MapStoreFactory;
import com.hazelcast.map.merge.LatestUpdateMapMergePolicy;
import io.jsync.app.ClusterApp;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Config;
import io.jsync.app.core.Logger;
import io.jsync.json.JsonObject;
import io.nebulosus.persistence.DummyDataPersistor;
import io.nebulosus.ipfs.IPFSCryptoPersistor;
import io.nebulosus.persistence.NBDataPreloadService;
import io.nebulosus.sockjs.SockJSAPIService;

public class NebulosusServer extends ClusterApp {

    @Override
    protected void prepareConfig(Config config) {

        // Let's go ahead and prepare the configuration that jsync.io can read.

        JsonObject rawConfig = config.rawConfig();

        JsonObject clusterConfig = rawConfig.getObject("cluster" , new JsonObject());
        clusterConfig.putString("data_persistor", DummyDataPersistor.class.getCanonicalName());

        // Ideally there is node and pnode
        // This means it is a regular nebulosus node.
        clusterConfig.putString("role", "node");

        rawConfig.putObject("cluster", clusterConfig);

    }

    @Override
    protected void prepareCluster(Cluster cluster) {

        Config config = cluster.config();

        JsonObject rawConfig = config.rawConfig();

        Logger logger = cluster.logger();

        logger.info("Preparing to start NebulosusServer");

        logger.info("Setting up Hazelcast IMap configuration for \"nbdata\".");

        // IMPORTANT We need to update the hazelcast configuration
        MapConfig nbDataMapConfig = new MapConfig();
        nbDataMapConfig.setName("nbdata");
        nbDataMapConfig.setInMemoryFormat(InMemoryFormat.BINARY);
        nbDataMapConfig.setBackupCount(0);
        nbDataMapConfig.setAsyncBackupCount(1);
        nbDataMapConfig.setEvictionPolicy(EvictionPolicy.NONE);
        nbDataMapConfig.setMergePolicy(LatestUpdateMapMergePolicy.class.getName());

        MapStoreConfig mapStoreConfig = new MapStoreConfig();
        mapStoreConfig.setInitialLoadMode(MapStoreConfig.InitialLoadMode.EAGER);
        mapStoreConfig.setWriteDelaySeconds(0);
        mapStoreConfig.setEnabled(true);

        mapStoreConfig.setFactoryImplementation((MapStoreFactory) (mapName, properties) -> new IPFSCryptoPersistor());

        // -- IMPORTANT --
        // We must create a map config for all data that we want to be persistent outside
        // of the default data persistence.. This will custom maps to be persisted.
        nbDataMapConfig.setMapStoreConfig(mapStoreConfig);

        // Let's add a hook to tell jsync.io to update the hazelcast config
        cluster.manager().addConfigHandler(hazelcastConfig -> {
            logger.info("Storing latest Hazelcast IMap configuration for \"nbdata\".");
            hazelcastConfig.addMapConfig(nbDataMapConfig);
        });

        logger.info("Adding base services.");

        cluster.addService(new NBDataPreloadService());

        boolean enabelSockJS = rawConfig.getBoolean("enable_sockjs");

        cluster.addService(new SockJSAPIService());

    }

    public static void main(String[] args){
        NebulosusServer nebulosusServer = new NebulosusServer();

        ClusterApp.initialize(nebulosusServer, "--join");
    }
}
