package io.nebulosus.sockjs;

import io.jsync.Async;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Config;
import io.jsync.app.core.Logger;
import io.jsync.app.core.service.ClusterService;
import io.jsync.eventbus.EventBus;
import io.jsync.http.HttpServer;
import io.jsync.json.JsonObject;
import io.jsync.sockjs.SockJSServer;

/**
 * This provides a simple SockJS based api for storing and retrieving information. Generally any language can easily
 * connect to this and implement their own client library.
 */
public class SockJSAPIService implements ClusterService {

    final public static int DEFAULT_PORT = 6174;

    private Async async = null;
    private EventBus eventBus = null;
    private HttpServer httpServer = null;
    private SockJSServer sockJSServer = null;
    private Logger logger = null;

    private boolean serviceStarted = false;

    @Override
    public void start(Cluster owner) {
        async = owner.async();
        eventBus = owner.eventBus();
        logger = owner.logger();

        Config config = owner.config();

        JsonObject sockServerConfig = config.rawConfig().getObject("sock", new JsonObject());

        int serverPort = sockServerConfig.getInteger("port", DEFAULT_PORT);
        String serverHost = sockServerConfig.getString("host", "127.0.0.1");

        boolean enabled = sockServerConfig.getBoolean("enabled", true);

        sockServerConfig.putBoolean("enabled", enabled);
        sockServerConfig.putNumber("port", serverPort);
        sockServerConfig.putString("host", serverHost);

        config.rawConfig().putObject("sock", sockServerConfig);

        config.save();

        if (enabled) {

            logger.info("SockJS support is currently enabled.");

            httpServer = async.createHttpServer();
            sockJSServer = owner.async().createSockJSServer(httpServer);

            JsonObject sockJSConfig = new JsonObject().putString("prefix", "/nebulosus.sock");

            // This will handle our SockJS requests.
            SockJSAPIHandler sockJSAPIHandler = new SockJSAPIHandler(owner);

            sockJSServer.installApp(sockJSConfig, sockJSAPIHandler);

            httpServer.setMaxWebSocketFrameSize(262144);

            logger.info("Attempting to start the SockJS server on " + serverHost + ":" + serverPort);

            httpServer.listen(serverPort, serverHost, asyncResult -> {
                if (!asyncResult.succeeded()) {
                    logger.fatal("Could not start SockJS server on " + serverHost + ":" + serverPort);
                    return;
                }
                serviceStarted = true;
                logger.info("SockJS server started on " + serverHost + ":" + serverPort);
            });
            return;
        }

        logger.info("SockJS support is currently disabled.");
    }

    @Override
    public void stop() {
        try {
            if (httpServer != null) {
                try {
                    logger.info("Stopping the local SockJS server.");
                    httpServer.close();
                } catch (Exception ignored) {
                }
            }
        } finally {
            serviceStarted = false;
            httpServer = null;
        }
    }

    @Override
    public boolean running() {
        return serviceStarted && httpServer != null;
    }

    @Override
    public String name() {
        return "SockJSAPIService";
    }
}
