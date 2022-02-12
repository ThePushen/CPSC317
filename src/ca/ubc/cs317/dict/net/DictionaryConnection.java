package ca.ubc.cs317.dict.net;

import ca.ubc.cs317.dict.model.Database;
import ca.ubc.cs317.dict.model.Definition;
import ca.ubc.cs317.dict.model.MatchingStrategy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.*;

/**
 * Created by Jonatan on 2017-09-09.
 */
public class DictionaryConnection {

    private static final int DEFAULT_PORT = 2628;
    Socket socket;
    BufferedReader in;
    PrintWriter out;

    /** Establishes a new connection with a DICT server using an explicit host and port number, and handles initial
     * welcome messages.
     *
     * @param host Name of the host where the DICT server is running
     * @param port Port number used by the DICT server
     * @throws DictConnectionException If the host does not exist, the connection can't be established, or the messages
     * don't match their expected value.
     */
    public DictionaryConnection(String host, int port) throws DictConnectionException {

        // TODO Add your code here
        try {
            socket = new Socket();
            SocketAddress socketAddress = new InetSocketAddress(host, port);
            socket.connect(socketAddress, 50000);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            Status status = Status.readStatus(in);

            // Initial connection check 220
            if (status.getStatusCode() != 220) {
                throw new DictConnectionException();
            }
            if (status.isNegativeReply()) {
                throw new DictConnectionException();
            }
            if (status.getStatusCode() == 530) {
                throw new DictConnectionException("Access denied");
            }
            if (status.getStatusCode() == 420) {
                throw new DictConnectionException("Server temporarily unavailable");
            }
            if (status.getStatusCode() == 421) {
                throw new DictConnectionException("Server shutting down at operator request");
            }
                // Welcome message
                System.out.println("Server connected");
        } catch (IOException e) {
            throw new DictConnectionException();
        }
    }

    /** Establishes a new connection with a DICT server using an explicit host, with the default DICT port number, and
     * handles initial welcome messages.
     *
     * @param host Name of the host where the DICT server is running
     * @throws DictConnectionException If the host does not exist, the connection can't be established, or the messages
     * don't match their expected value.
     */
    public DictionaryConnection(String host) throws DictConnectionException {
        this(host, DEFAULT_PORT);
    }

    /** Sends the final QUIT message and closes the connection with the server. This function ignores any exception that
     * may happen while sending the message, receiving its reply, or closing the connection.
     *
     */
    public synchronized void close() {

        // TODO Add your code here
        try {
            // QUIT message
            out.println("QUIT");

            // Closing connection check 221
            Status status = Status.readStatus(in);
            if (status.getStatusCode() != 221) {
                throw new DictConnectionException();
            }

            // close socket
            socket.close();
        } catch(IOException | DictConnectionException e) {
            System.out.println("error");
        }
    }

    /** Requests and retrieves all definitions for a specific word.
     *
     * @param word The word whose definition is to be retrieved.
     * @param database The database to be used to retrieve the definition. A special database may be specified,
     *                 indicating either that all regular databases should be used (database name '*'), or that only
     *                 definitions in the first database that has a definition for the word should be used
     *                 (database '!').
     * @return A collection of Definition objects containing all definitions returned by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Collection<Definition> getDefinitions(String word, Database database) throws DictConnectionException {
        Collection<Definition> set = new ArrayList<>();

        // TODO Add your code here
        String databaseName = database.getName();
        String message = "DEFINE " + databaseName + " \"" + word + "\"\r\n";
        out.println(message);

        Status status = Status.readStatus(in);

        try {
            if (status.getStatusCode() == 550) {
                System.out.println("Invalid database");
                return set;
            }
            if (status.getStatusCode() == 552) {
                System.out.println("No match");
                return set;
            }
            // n definitions retrieved
            if (status.getStatusCode() != 150) {
                throw new DictConnectionException();
            }
            String details = status.getDetails();
            int num = Integer.parseInt(DictStringParser.splitAtoms(details)[0]);
            while (num > 0) {
                status = Status.readStatus(in);
                details = status.getDetails();
                // check before move on
                if (status.getStatusCode() != 151) {
                    throw new DictConnectionException();
                }
                Definition definition = new Definition(DictStringParser.splitAtoms(details)[0],
                        DictStringParser.splitAtoms(details)[1]);
                String def = in.readLine();
                while (!def.equals(".")) {
                    definition.appendDefinition(def);
                    def = in.readLine();
                }
                set.add(definition);
                num--;
            }

            // check Status
            status = Status.readStatus(in);
            if (status.getStatusCode() != 250) {
                throw new DictConnectionException();
            }
        } catch (IOException e) {
            throw new DictConnectionException();
        }

        return set;
    }

    /** Requests and retrieves a list of matches for a specific word pattern.
     *
     * @param word     The word whose definition is to be retrieved.
     * @param strategy The strategy to be used to retrieve the list of matches (e.g., prefix, exact).
     * @param database The database to be used to retrieve the definition. A special database may be specified,
     *                 indicating either that all regular databases should be used (database name '*'), or that only
     *                 matches in the first database that has a match for the word should be used (database '!').
     * @return A set of word matches returned by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Set<String> getMatchList(String word, MatchingStrategy strategy, Database database) throws DictConnectionException {
        Set<String> set = new LinkedHashSet<>();

        // TODO Add your code here
        String message = "MATCH" + " " + database.getName() + " " + strategy.getName() + " " + "\"" + word + "\"\r\n";
        out.println(message);
        Status status = Status.readStatus(in);
        try {
            if (status.getStatusCode() == 550) {
                System.out.println("Invalid database");
                return set;
            }
            if (status.getStatusCode() == 551) {
                System.out.println("Invalid strategy");
                return set;
            }
            if (status.getStatusCode() == 552) {
                System.out.println("No match");
                return set;
            }
            if (status.getStatusCode() != 152) {
                throw new DictConnectionException();
            }
            String ma = in.readLine();
            while (!ma.equals(".")) {
                set.add(DictStringParser.splitAtoms(ma)[1]);
                ma = in.readLine();
            }

            // check Status
            status = Status.readStatus(in);
            if (status.getStatusCode() != 250) {
                throw new DictConnectionException();
            }
        } catch (IOException e) {
            throw new DictConnectionException();
        }

        return set;
    }

    /** Requests and retrieves a map of database name to an equivalent database object for all valid databases used in the server.
     *
     * @return A map of Database objects supported by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Map<String, Database> getDatabaseList() throws DictConnectionException {
        Map<String, Database> databaseMap = new HashMap<>();

        // TODO Add your code here
        String message = "SHOW DB";
        out.println(message);
        Status status = Status.readStatus(in);
        try {
            if (status.getStatusCode() == 554) {
                System.out.println("No databases present");
                return databaseMap;
            }
            if (status.getStatusCode() != 110) {
                throw new DictConnectionException();
            }
            String da = in.readLine();
            Database database;
            while (!da.equals(".")) {
                database = new Database(DictStringParser.splitAtoms(da)[0],
                        DictStringParser.splitAtoms(da)[1]);
                // add to database
                databaseMap.put(database.getName(), database);
                da = in.readLine();
            }

            // check Status
            status = Status.readStatus(in);
            if (status.getStatusCode() != 250) {
                throw new DictConnectionException();
            }
        } catch (IOException e) {
            throw new DictConnectionException();
        }

        return databaseMap;
    }

    /** Requests and retrieves a list of all valid matching strategies supported by the server.
     *
     * @return A set of MatchingStrategy objects supported by the server.
     * @throws DictConnectionException If the connection was interrupted or the messages don't match their expected value.
     */
    public synchronized Set<MatchingStrategy> getStrategyList() throws DictConnectionException {
        Set<MatchingStrategy> set = new LinkedHashSet<>();

        // TODO Add your code here
        String message = "SHOW STRAT";
        out.println(message);
        Status status = Status.readStatus(in);
        try {
            if (status.getStatusCode() == 555) {
                System.out.println("No strategies available");
                return set;
            }
            if (status.getStatusCode() != 111) {
                throw new DictConnectionException();
            }
            String str = in.readLine();
            while (!str.equals(".")) {
                // add top strategy
                MatchingStrategy strategy = new MatchingStrategy(DictStringParser.splitAtoms(str)[0],
                        DictStringParser.splitAtoms(str)[1]);
                set.add(strategy);
                str = in.readLine();
            }

            // check Status
            status = Status.readStatus(in);
            if (status.getStatusCode() != 250) {
                throw new DictConnectionException();
            }
        } catch (IOException e) {
            throw new DictConnectionException();
        }

        return set;
    }
}
