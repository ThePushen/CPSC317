package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.IntStream;

public class DNSMessage {
    public static final int MAX_DNS_MESSAGE_LENGTH = 512;
    public static final int QUERY = 0;
    public List<ResourceRecord> answer = new ArrayList<>();
    /**
     * TODO:  You will add additional constants and fields
     */
    private final Map<String, Integer> nameToPosition = new HashMap<>();
    private final Map<Integer, String> positionToName = new HashMap<>();
    private final ByteBuffer buffer;


    /**
     * Initializes an empty DNSMessage with the given id.
     *
     * @param id The id of the message.
     */
    public DNSMessage(short id) {
        this.buffer = ByteBuffer.allocate(MAX_DNS_MESSAGE_LENGTH);
        // TODO: Complete this method
        setID(id);
        buffer.position(12);
    }

    /**
     * Initializes a DNSMessage with the first length bytes of the given byte array.
     *
     * @param recvd The byte array containing the received message
     * @param length The length of the data in the array
     */
    public DNSMessage(byte[] recvd, int length) {
        buffer = ByteBuffer.wrap(recvd, 0, length);
        // TODO: Complete this method
        buffer.position(12);
    }

    /**
     * Getters and setters for the various fixed size and fixed location fields of a DNSMessage
     * TODO:  They are all to be completed
     */
    public int getID() {
        return buffer.getShort(0) & 0xffff;
    }

    public void setID(int id) {
        buffer.putShort(0, (short) id);
    }

    public boolean getQR() {
        int check = (buffer.get(2) >> 7) & 0x1;
        return check == 1;
    }

    public void setQR(boolean qr) {
        if (qr) {
            buffer.put(2, (byte) (buffer.get(2) | 0b10000000));
        } else {
            buffer.put(2, (byte) (buffer.get(2) & 0b01111111));
        }
    }

    public boolean getAA() {
        int check =  (buffer.get(2) >> 2) & 0x1;
        return check == 1;
    }

    public void setAA(boolean aa) {
        if (aa) {
            buffer.put(2, (byte) (buffer.get(2) | 0b00000100));
        } else {
            buffer.put(2, (byte) (buffer.get(2) & 0b11111011));
        }
    }

    public int getOpcode() {
        return (buffer.get(2) >> 3) & 0b00001111;
    }

    public void setOpcode(int opcode) {
        buffer.put(2, (byte) ((byte) (buffer.get(2) & 0b10000111) | ((opcode & 0xf) << 3)));
    }

    public boolean getTC() {
        int check = (buffer.get(2) >> 1) & 0x1;
        return check == 1;
    }

    public void setTC(boolean tc) {
        if (tc) {
            buffer.put(2, (byte) (buffer.get(2) | 0b00000010));
        } else {
            buffer.put(2, (byte) (buffer.get(2) & 0b11111101));
        }
    }

    public boolean getRD() {
        int check = (buffer.get(2)) & 0x1;
        return check == 1;
    }

    public void setRD(boolean rd) {
        if (rd) {
            buffer.put(2, (byte) (buffer.get(2) | 0b00000001));
        } else {
            buffer.put(2, (byte) (buffer.get(2) & 0b11111110));
        }
    }

    public boolean getRA() {
        int check = (buffer.get(3) >> 7) & 0x1;
        return check == 1;
    }

    public void setRA(boolean ra) {
        if (ra) {
            buffer.put(3, (byte) (buffer.get(3) | 0b10000000));
        } else {
            buffer.put(3, (byte) (buffer.get(3) & 0b01111111));
        }
    }

    public int getRcode() {
        return buffer.get(3) & 0xf;
    }

    public void setRcode(int rcode) {
        buffer.put(3, (byte) ((byte) (buffer.get(3) & 0b11110000) | (rcode & 0xf)));
    }

    public int getQDCount() {return buffer.getShort(4) & 0xffff;}

    public void setQDCount(int count) {
        buffer.putShort(4, (short) count);
    }

    public int getANCount() {
        return buffer.getShort(6) & 0xffff;
    }

    public void setANCount(int count) { buffer.putShort(6, (short) count); }

    public int getNSCount() {
        return buffer.getShort(8) & 0xffff;
    }

    public void setNSCount(int count) { buffer.putShort(8, (short) count); }

    public int getARCount() {
        return buffer.getShort(10) & 0xffff;
    }

    public void setARCount(int count) {
        buffer.putShort(10, (short) count);
    }

    /**
     * Return the name at the current position() of the buffer.  This method is provided for you,
     * but you should ensure that you understand what it does and how it does it.
     *
     * The trick is to keep track of all the positions in the message that contain names, since
     * they can be the target of a pointer.  We do this by storing the mapping of position to
     * name in the positionToName map.
     *
     * @return The decoded name
     */
    public String getName() {
        // Remember the starting position for updating the name cache
        int start = buffer.position();
        int len = buffer.get() & 0xff;
        if (len == 0) return "";
        if ((len & 0xc0) == 0xc0) {  // This is a pointer
            int pointer = ((len & 0x3f) << 8) | (buffer.get() & 0xff);
            String suffix = positionToName.get(pointer);
            assert suffix != null;
            positionToName.put(start, suffix);
            return suffix;
        }
        byte[] bytes = new byte[len];
        buffer.get(bytes, 0, len);
        String label = new String(bytes, StandardCharsets.UTF_8);
        String suffix = getName();
        String answer = suffix.isEmpty() ? label : label + "." + suffix;
        positionToName.put(start, answer);
        return answer;
    }

    /**
     * The standard toString method that displays everything in a message.
     * @return The string representation of the message
     */
    public String toString() {
        // Remember the current position of the buffer so we can put it back
        // Since toString() can be called by the debugger, we want to be careful to not change
        // the position in the buffer.  We remember what it was and put it back when we are done.
        int end = buffer.position();
        final int DataOffset = 12;
        try {
            StringBuilder sb = new StringBuilder();
            sb.append("ID: ").append(getID()).append(' ');
            sb.append("QR: ").append(getQR()).append(' ');
            sb.append("OP: ").append(getOpcode()).append(' ');
            sb.append("AA: ").append(getAA()).append('\n');
            sb.append("TC: ").append(getTC()).append(' ');
            sb.append("RD: ").append(getRD()).append(' ');
            sb.append("RA: ").append(getRA()).append(' ');
            sb.append("RCODE: ").append(getRcode()).append(' ')
                    .append(dnsErrorMessage(getRcode())).append('\n');
            sb.append("QDCount: ").append(getQDCount()).append(' ');
            sb.append("ANCount: ").append(getANCount()).append(' ');
            sb.append("NSCount: ").append(getNSCount()).append(' ');
            sb.append("ARCount: ").append(getARCount()).append('\n');
            buffer.position(DataOffset);
            showQuestions(getQDCount(), sb);
            showRRs("Authoritative", getANCount(), sb);
            showRRs("Name servers", getNSCount(), sb);
            showRRs("Additional", getARCount(), sb);
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
            return "toString failed on DNSMessage";
        }
        finally {
            buffer.position(end);
        }
    }

    /**
     * Add the text representation of all the questions (there are nq of them) to the StringBuilder sb.
     *
     * @param nq Number of questions
     * @param sb Collects the string representations
     */
    private void showQuestions(int nq, StringBuilder sb) {
        sb.append("Question [").append(nq).append("]\n");
        for (int i = 0; i < nq; i++) {
            DNSQuestion question = getQuestion();
            sb.append('[').append(i).append(']').append(' ').append(question).append('\n');
        }
    }

    /**
     * Add the text representation of all the resource records (there are nrrs of them) to the StringBuilder sb.
     *
     * @param kind Label used to kind of resource record (which section are we looking at)
     * @param nrrs Number of resource records
     * @param sb Collects the string representations
     */
    private void showRRs(String kind, int nrrs, StringBuilder sb) {
        sb.append(kind).append(" [").append(nrrs).append("]\n");
        for (int i = 0; i < nrrs; i++) {
            ResourceRecord rr = getRR();
            sb.append('[').append(i).append(']').append(' ').append(rr).append('\n');
        }
    }

    /**
     * Decode and return the question that appears next in the message.  The current position in the
     * buffer indicates where the question starts.
     *
     * @return The decoded question
     */
    public DNSQuestion getQuestion() {
        // TODO: Complete this method
        return new DNSQuestion(getName(), RecordType.getByCode(buffer.getChar()), RecordClass.getByCode(buffer.getChar()));
    }

    /**
     * Decode and return the resource record that appears next in the message.  The current
     * position in the buffer indicates where the resource record starts.
     *
     * @return The decoded resource record
     */
    public ResourceRecord getRR() {
        // TODO: Complete this method
        //int length = buffer.array().length;
        DNSQuestion question = getQuestion();
        int ttl = buffer.getInt();
        //int range = length - buffer.position() - 1;
        // ResourceRecord rr;
        int length = buffer.getShort();
        if (question.getRecordType() == RecordType.A || question.getRecordType() == RecordType.AAAA) {
            try {
                byte[] newArray = new byte[length];
                for (int i = 0; i < length; i++) {
                    newArray[i] = buffer.get();
                }
                return new ResourceRecord(question, ttl, InetAddress.getByAddress(newArray));
            } catch (Exception ignored) {
            }
        } else if (question.getRecordType() == RecordType.MX) {
            buffer.getShort();
            return new ResourceRecord(question, ttl, getName());
        } else if (question.getRecordType() == RecordType.NS || question.getRecordType() == RecordType.CNAME) {
            return new ResourceRecord(question, ttl, getName());
        } else {
            byte[] arr = new byte[length];
            for (int j = 0; j < length; j++) {
                arr[j] = buffer.get();
            }
            String toHex = byteArrayToHexString(arr);
            return new ResourceRecord(question, ttl, toHex);
        }
        return new ResourceRecord(question, ttl, getName());
    }

    /**
     * Helper function that returns a hex string representation of a byte array. May be used to represent the result of
     * records that are returned by a server but are not supported by the application (e.g., SOA records).
     *
     * @param data a byte array containing the record data.
     * @return A string containing the hex value of every byte in the data.
     */
    public static String byteArrayToHexString(byte[] data) {
        return IntStream.range(0, data.length).mapToObj(i -> String.format("%02x", data[i])).reduce("", String::concat);
    }

    /**
     * Add an encoded name to the message. It is added at the current position and uses compression
     * as much as possible.  Compression is accomplished by remembering the position of every added
     * label.
     *
     * @param name The name to be added
     */
    public void addName(String name) {
        String label;
        while (name.length() > 0) {
            Integer offset = nameToPosition.get(name);
            if (offset != null) {
                int pointer = offset;
                pointer |= 0xc000;
                buffer.putShort((short)pointer);
                return;
            } else {
                nameToPosition.put(name, buffer.position());
                int dot = name.indexOf('.');
                label = (dot > 0) ? name.substring(0, dot) : name;
                buffer.put((byte)label.length());
                for (int j = 0; j < label.length(); j++) {
                    buffer.put((byte)label.charAt(j));
                }
                name = (dot > 0) ? name.substring(dot + 1) : "";
            }
        }
        buffer.put((byte)0);
    }

    /**
     * Add an encoded question to the message at the current position.
     * @param question The question to be added
     */
    public void addQuestion(DNSQuestion question) {
        // TODO: Complete this method
        addName(question.getHostName());
        addQType(question.getRecordType());
        addQClass(question.getRecordClass());
        setQDCount(getQDCount() + 1);
    }

    /**
     * Add an encoded resource record to the message at the current position.
     * @param rr The resource record to be added
     * @param section A string describing the section that the rr should be added to
     */
    public void addResourceRecord(ResourceRecord rr, String section) {
        // TODO: Complete this method
        addName(rr.getHostName());
        RecordType record = rr.getRecordType();
        addQType(record);
        addQClass(rr.getRecordClass());
        int rrttl = (int) rr.getRemainingTTL();
        buffer.putInt(rrttl);
        if (record == RecordType.A) {
            buffer.putShort((byte) 0x0004);
            byte[] rrga = rr.getInetResult().getAddress();
            buffer.put(rrga);
        } else if (record == RecordType.AAAA) {
            buffer.putShort((byte) 0x0010);
            byte[] rrga = rr.getInetResult().getAddress();
            buffer.put(rrga);
        } else if (record == RecordType.MX) {
            int rdlength_pos = buffer.position();
            buffer.putShort((short) 0);
            buffer.putShort((short) 0);
            addName(rr.getTextResult());
            int length = buffer.position() - rdlength_pos - 2;
            buffer.putShort(rdlength_pos, (short) length);
        } else {
            int rdlength_pos = buffer.position();
            buffer.putShort((short) 0);
            addName(rr.getTextResult());
            int length = buffer.position() - rdlength_pos - 2;
            // byte[] i = rr.getTextResult().getBytes(StandardCharsets.UTF_8);
            buffer.putShort(rdlength_pos, (short) length);
        }
        switch (section) {
            case "answer":
                setANCount(getANCount() + 1);
                break;
            case "nameserver":
                setNSCount(getNSCount() + 1);
                break;
            case "additional":
                setARCount(getARCount() + 1);
                break;
        }
    }

    /**
     * Add an encoded type to the message at the current position.
     * @param recordType The type to be added
     */
    private void addQType(RecordType recordType) {
        // TODO: Complete this method
        short rt = (short) recordType.getCode();
        buffer.putShort(rt);
    }

    /**
     * Add an encoded class to the message at the current position.
     * @param recordClass The class to be added
     */
    private void addQClass(RecordClass recordClass) {
        // TODO: Complete this method
        short rc = (short) recordClass.getCode();
        buffer.putShort(rc);
    }

    /**
     * Return a byte array that contains all the data comprising this message.  The length of the
     * array will be exactly the same as the current position in the buffer.
     * @return A byte array containing this message's data
     */
    public byte[] getUsed() {
        // TODO: Complete this method
        int pos = buffer.position();
        byte[] newArray = new byte[pos];
        for (int i = 0; i < pos; i++) {
            newArray[i] = buffer.get(i);
        }
        return newArray;
    }

    /**
     * Returns a string representation of a DNS error code.
     *
     * @param error The error code received from the server.
     * @return A string representation of the error code.
     */
    public static String dnsErrorMessage(int error) {
        final String[] errors = new String[]{
                "No error", // 0
                "Format error", // 1
                "Server failure", // 2
                "Name error (name does not exist)", // 3
                "Not implemented (parameters not supported)", // 4
                "Refused" // 5
        };
        if (error >= 0 && error < errors.length)
            return errors[error];
        return "Invalid error message";
    }
}
