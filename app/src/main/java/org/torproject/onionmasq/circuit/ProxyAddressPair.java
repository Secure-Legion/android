package org.torproject.onionmasq.circuit;

import java.util.Objects;

public class ProxyAddressPair {

    /**
     * The source IP:port for the connection, from the Android side.
     */
    public String proxySrc;
    /**
     * The destination IP:port *on the VPN side*, i.e. a fake address the VPN gave out.
     */
    public String proxyDst;

    @Override
    public String toString() {
        return "ProxyAddressPair{" +
                "proxySrc='" + proxySrc + '\'' +
                ", proxyDst='" + proxyDst + '\'' +
                '}';
    }

    public ProxyAddressPair(String proxySrc, String proxyDst) {
        this.proxySrc = proxySrc;
        this.proxyDst = proxyDst;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ProxyAddressPair)) return false;

        ProxyAddressPair that = (ProxyAddressPair) o;

        if (!Objects.equals(proxySrc, that.proxySrc))
            return false;
        return Objects.equals(proxyDst, that.proxyDst);
    }

    @Override
    public int hashCode() {
        int result = proxySrc != null ? proxySrc.hashCode() : 0;
        result = 31 * result + (proxyDst != null ? proxyDst.hashCode() : 0);
        return result;
    }
}
