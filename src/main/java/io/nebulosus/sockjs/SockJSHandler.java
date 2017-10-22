package io.nebulosus.sockjs;

import com.hazelcast.core.IMap;
import io.jsync.Async;
import io.jsync.Handler;
import io.jsync.app.core.Cluster;
import io.jsync.app.core.Logger;
import io.jsync.buffer.Buffer;
import io.jsync.sockjs.SockJSSocket;

import java.util.*;
import java.util.zip.CRC32;

/**
 * This handles SockJS requests allowing a simple interface to Nebulosus.
 */
public class SockJSHandler implements Handler<SockJSSocket> {

    private Logger logger = null;

    private Async localAsync = null;

    private Map<SockJSSocket, Long> clientSessions = new HashMap<>();
    private IMap<String, Object> nbdata = null;

    public SockJSHandler(Cluster cluster){
        // This is where we are currently storing any data that
        // Nebulosus stores.
        nbdata = cluster.data().getMap("nbdata", false);

        this.logger = cluster.logger();
        this.localAsync = cluster.localAsync();
    }

    @Override
    public void handle(final SockJSSocket sock) {
        // After about 5 seconds we will disconnect if handshake has not been received.
        long sessionTimeout = localAsync.setTimer(5000, event -> {
             try {
                 sock.close();
                 clientSessions.remove(sock);
             } catch (Exception ignored){
             }
        });

        sock.dataHandler(new Handler<Buffer>() {

            //private void errorResponse();

            @Override
            public void handle(final Buffer buffer) {

                final int cmd = buffer.getByte(0);


                int pos = 1;

                // Session Handshake - This is not for
                // security purposes. This is so the client
                // can properly read replies for a specific request.
                if(cmd == 64){
                    // Let's attempt to decode the handshake.

                    int uuidLen = buffer.getByte(pos);
                    pos += 1;

                    String uuid = buffer.getString(pos, uuidLen + pos);
                    pos += uuidLen;

                    CRC32 crc = new CRC32();
                    crc.update(uuid.getBytes());

                    long nCRC = crc.getValue();

                    int crcLen = buffer.getByte(pos);
                    pos += 1;

                    long rCRC = Long.parseLong(buffer.getString(pos, pos + crcLen));

                    // If this does not match then we will automatically
                    // dis connect the client. This isn't a security feature
                    // at all. This is more or less so the client can identify responses
                    // and it can identify the client.
                    if(rCRC == nCRC){

                        // We need to ensure we do not
                        // kill the session via timeout.
                        localAsync.cancelTimer(sessionTimeout);

                        clientSessions.put(sock, rCRC);

                        // Let's go ahead and reply back with a
                        // handshake verification. This means the
                        // client can now start requesting data.
                        Buffer handShakeResp = new Buffer();
                        handShakeResp.appendByte((byte) 65); // this means we have accepted the connection
                        handShakeResp.appendString(uuid);

                        sock.write(handShakeResp);
                        return;
                    }
                }

                // Looks like there's no session!
                if(!clientSessions.containsKey(sock)){
                    sock.close();
                    return;
                }
                // Let's process commands here

                if(cmd == 82){

                    String key = null;

                    byte keyType = buffer.getByte(pos);
                    pos += 1;
                    if(keyType == 97){
                        int keySize = buffer.getInt(pos);
                        pos += 4;
                        key = buffer.getString(pos, keySize + pos);
                        pos += keySize;
                    }

                    if(key == null){
                        // TODO
                        // Respond with error.
                        // Or maybe just disconnect since it's malformed data.
                        sock.close();
                        return;
                    }

                    // TODO we are currently sending strings back

                    Object data = nbdata.get(key);

                    if(buffer.length() > pos + 4){
                        int uuidLen = buffer.getInt(pos);
                        pos += 4;

                        if(buffer.length() >= pos + uuidLen){
                            String callbackId = buffer.getString(pos, pos + uuidLen);

                            Buffer replyCB = new Buffer();
                            replyCB.appendByte((byte) 13);

                            String strData = data.toString();

                            replyCB.appendInt(strData.length());

                            replyCB.appendString(strData);

                            replyCB.appendInt(callbackId.length());
                            replyCB.appendString(callbackId);

                            sock.write(replyCB);
                        }
                    }
                } else if(cmd == 83){
                    // Store

                    // TODO we are currently only storing strings.

                    String key = null;
                    Object value = null;

                    byte keyType = buffer.getByte(pos);
                    pos += 1;
                    byte valType = buffer.getByte(pos);
                    pos += 1;

                    if(keyType == 97){
                        int keySize = buffer.getInt(pos);
                        pos += 4;
                        key = buffer.getString(pos, keySize + pos);
                        pos += keySize;
                    }

                    if(valType == 97){
                        int valSize = buffer.getInt(pos);
                        pos += 4;
                        value = buffer.getString(pos, valSize + pos);
                        pos += valSize;
                    }

                    if(key == null || value == null){
                        // TODO
                        // Respond with error.
                        // Or maybe just disconnect since it's malformed data.
                        sock.close();
                        return;
                    }

                    nbdata.set(key, value);

                    if(buffer.length() > pos + 4){
                        int uuidLen = buffer.getInt(pos);
                        pos += 4;

                        if(buffer.length() >= pos + uuidLen){

                            int finalPos = pos;
                            localAsync.runOnContext(event -> {
                                String callbackId = buffer.getString(finalPos, finalPos + uuidLen);

                                Buffer replyCB = new Buffer();
                                replyCB.appendByte((byte) 12);
                                replyCB.appendInt(callbackId.length());
                                replyCB.appendString(callbackId);

                                sock.write(replyCB);
                            });
                        }
                    }
                }
            }
        });

        sock.endHandler(event -> {
            localAsync.cancelTimer(sessionTimeout);
            clientSessions.remove(sock);
        });
    }
}
