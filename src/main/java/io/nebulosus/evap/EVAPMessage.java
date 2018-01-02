package io.nebulosus.evap;

import io.jsync.buffer.Buffer;

/**
 * This represents decrypted message data for the evaporation protocol.
 */
public class EVAPMessage {

    /**
     * 201701 is the firs iteration of the evaporation protocol. This is currently in alpha.
     */
    final public static int PROTOCOL_VERSION = 201701;

    // TODO implement reply peer.

    private Buffer payload = null;
    private Buffer data = null;

    private String token = null;

    private String payloadPeer = null;
    private PayloadType payloadType = null;

    protected EVAPMessage(Buffer payload, Buffer data){
        this.payload = payload;
        this.data = data;

        this.payloadPeer = _getPayloadPeer();
        this.payloadType = _getPayloadType();

        this.token = payload.getString(12, 12 + payload.getInt(8));

    }

    public String getMessageToken(){
        return token;
    }

    /**
     * Returns the version of the evaporation protocol that was used to send this message.
     *
     * @return returns it as an integer.
     */
    public double getProtocolVersion(){
        return payload.getInt(0);
    }

    /**
     * This will go ahead and return the payload type.
     *
     * @return the payload type for this message
     */
    public PayloadType getPayloadType(){
        return payloadType;
    }

    public Buffer getPayload(){
        return payload;
    }

    public Buffer getData(){
        return data;
    }

    public String getPayloadPeer() {
        return payloadPeer;
    }

    private PayloadType _getPayloadType(){
        int type = payload.getInt(4);

        if(type == PayloadType.DEFAULT.code){
            return PayloadType.DEFAULT;
        } else if(type == PayloadType.PIN_DATA.code){
            return PayloadType.PIN_DATA;
        } else if(type == PayloadType.ACK.code){
            return PayloadType.ACK;
        } else if (type == PayloadType.PEER_RELAY_BROADCAST.code) {
            return PayloadType.PEER_RELAY_BROADCAST;
        } else if (type == PayloadType.MESSAGE_RELAY.code) {
            return PayloadType.MESSAGE_RELAY;
        } else if (type == PayloadType.PEER_LOG.code) {
            return PayloadType.PEER_LOG;
        }
        return null;
    }

    private String _getPayloadPeer() {
        int offset1 = payload.getInt(8);
        int offset2 = payload.getInt(12 + offset1);
        int offset3 = payload.getInt(16 + offset1 + offset2);
        int offset4 = payload.getInt(20 + offset3 + offset2 + offset1);

        return payload.getString(offset3 + offset2 + offset1 + 24, offset4 + offset3 + offset2 + offset1 + 24);
    }

    /**
     * This represents a message payload type for the evaporation protocol. Currently there are only 6 payload types.
     */
    public enum PayloadType {
        /**
         * The default payload type. In reality anything could be sent along with this.
         */
        DEFAULT(100),
        /**
         * Represents an acknowledgement message.
         */
        ACK(101),
        /**
         * Represents a request to pin a specific hash.
         */
        PIN_DATA(1001),
        /**
         * Represents a request to unpin a specific hash.
         */
        UNPIN_DATA(1001),
        /**
         * Represents a broadcast message sent out by a relay peer.
         */
        PEER_RELAY_BROADCAST(2000),
        /**
         * This represents a message that is destined to be relayed.
         */
        MESSAGE_RELAY(2001),
        /**
         * This represents a log message from a trusted peer.
         */
        PEER_LOG(2100);

        public final int code;

        PayloadType(int code) {
            this.code = code;
        }
    }
}
