/*
 * Copyright 2021-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.onosproject.kubevirtnetworking.api;

import com.google.common.base.MoreObjects;
import com.google.common.collect.ImmutableSet;
import org.onlab.packet.IpAddress;

import java.util.Objects;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;
import static org.onosproject.kubevirtnetworking.api.KubevirtNetwork.Type.FLAT;

/**
 * Default implementation class of kubevirt network.
 */
public final class DefaultKubevirtNetwork implements KubevirtNetwork {

    private static final String NOT_NULL_MSG = "Network % cannot be null";

    private final String networkId;
    private final Type type;
    private final String name;
    private final Integer mtu;
    private final String segmentId;
    private final IpAddress gatewayIp;
    private final String cidr;
    private final Set<KubevirtHostRoute> hostRoutes;
    private final KubevirtIpPool ipPool;

    /**
     * Default constructor.
     *
     * @param networkId         network identifier
     * @param type              type of network
     * @param name              network name
     * @param mtu               network MTU
     * @param segmentId         segment identifier
     * @param gatewayIp         gateway IP address
     * @param cidr              CIDR of network
     * @param hostRoutes        a set of host routes
     * @param ipPool            IP pool
     */
    public DefaultKubevirtNetwork(String networkId, Type type, String name,
                                  Integer mtu, String segmentId, IpAddress gatewayIp,
                                  String cidr, Set<KubevirtHostRoute> hostRoutes,
                                  KubevirtIpPool ipPool) {
        this.networkId = networkId;
        this.type = type;
        this.name = name;
        this.mtu = mtu;
        this.segmentId = segmentId;
        this.gatewayIp = gatewayIp;
        this.cidr = cidr;
        this.hostRoutes = hostRoutes;
        this.ipPool = ipPool;
    }

    @Override
    public String networkId() {
        return networkId;
    }

    @Override
    public Type type() {
        return type;
    }

    @Override
    public String name() {
        return name;
    }

    @Override
    public Integer mtu() {
        return mtu;
    }

    @Override
    public String segmentId() {
        return segmentId;
    }

    @Override
    public IpAddress gatewayIp() {
        return gatewayIp;
    }

    @Override
    public String cidr() {
        return cidr;
    }

    @Override
    public Set<KubevirtHostRoute> hostRoutes() {
        if (hostRoutes == null || hostRoutes.size() == 0) {
            return ImmutableSet.of();
        } else {
            return ImmutableSet.copyOf(hostRoutes);
        }
    }

    @Override
    public KubevirtIpPool ipPool() {
        return ipPool;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        DefaultKubevirtNetwork that = (DefaultKubevirtNetwork) o;
        return networkId.equals(that.networkId) && type == that.type &&
                name.equals(that.name) && mtu.equals(that.mtu) &&
                gatewayIp.equals(that.gatewayIp) &&
                cidr.equals(that.cidr) && hostRoutes.equals(that.hostRoutes) &&
                ipPool.equals(that.ipPool);
    }

    @Override
    public int hashCode() {
        return Objects.hash(networkId, type, name, mtu, segmentId, gatewayIp,
                cidr, hostRoutes, ipPool);
    }

    @Override
    public String toString() {
        return MoreObjects.toStringHelper(this)
                .add("networkId", networkId)
                .add("type", type)
                .add("name", name)
                .add("mtu", mtu)
                .add("segmentId", segmentId)
                .add("gatewayIp", gatewayIp)
                .add("cidr", cidr)
                .add("hostRouts", hostRoutes)
                .add("ipPool", ipPool)
                .toString();
    }

    /**
     * Returns new builder instance.
     *
     * @return kubevirt port builder
     */
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder implements KubevirtNetwork.Builder {

        private String networkId;
        private Type type;
        private String name;
        private Integer mtu;
        private String segmentId;
        private IpAddress gatewayIp;
        private String cidr;
        private Set<KubevirtHostRoute> hostRouts;
        private KubevirtIpPool ipPool;

        @Override
        public KubevirtNetwork build() {
            checkArgument(networkId != null, NOT_NULL_MSG, "networkId");
            checkArgument(type != null, NOT_NULL_MSG, "type");
            checkArgument(name != null, NOT_NULL_MSG, "name");
            checkArgument(mtu != null, NOT_NULL_MSG, "mtu");
            checkArgument(gatewayIp != null, NOT_NULL_MSG, "gatewayIp");
            checkArgument(cidr != null, NOT_NULL_MSG, "cidr");
            checkArgument(ipPool != null, NOT_NULL_MSG, "ipPool");

            if (type != FLAT) {
                checkArgument(segmentId != null, NOT_NULL_MSG, "segmentId");
            }

            return new DefaultKubevirtNetwork(networkId, type, name, mtu, segmentId,
                    gatewayIp, cidr, hostRouts, ipPool);
        }

        @Override
        public Builder networkId(String networkId) {
            this.networkId = networkId;
            return this;
        }

        @Override
        public Builder name(String name) {
            this.name = name;
            return this;
        }

        @Override
        public Builder type(Type type) {
            this.type = type;
            return this;
        }

        @Override
        public Builder mtu(Integer mtu) {
            this.mtu = mtu;
            return this;
        }

        @Override
        public Builder segmentId(String segmentId) {
            this.segmentId = segmentId;
            return this;
        }

        @Override
        public Builder gatewayIp(IpAddress ipAddress) {
            this.gatewayIp = ipAddress;
            return this;
        }

        @Override
        public Builder cidr(String cidr) {
            this.cidr = cidr;
            return this;
        }

        @Override
        public Builder ipPool(KubevirtIpPool ipPool) {
            this.ipPool = ipPool;
            return this;
        }

        @Override
        public Builder hostRoutes(Set<KubevirtHostRoute> hostRoutes) {
            this.hostRouts = hostRoutes;
            return this;
        }
    }
}
