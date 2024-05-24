#define private public
#include "directory.h"
#undef private
#define protected public
#include "orch.h"
#undef protected
#include "ut_helper.h"
#include "mock_orchagent_main.h"
#include "mock_table.h"

extern string gMySwitchType;

namespace flowcounterrouteorch_test
{
    using namespace std;
    shared_ptr<swss::DBConnector> m_app_db;
    shared_ptr<swss::DBConnector> m_config_db;
    shared_ptr<swss::DBConnector> m_state_db;
    shared_ptr<swss::DBConnector> m_chassis_app_db;

    int num_created_counter;
    sai_counter_api_t ut_sai_counter_api;
    sai_counter_api_t *pold_sai_counter_api;
    sai_create_counter_fn old_create_counter;
    sai_remove_counter_fn old_remove_counter;

    sai_status_t _ut_stub_create_counter(
        _Out_ sai_object_id_t *counter_id,
	    _In_ sai_object_id_t switch_id,
	    _In_ uint32_t attr_count,
	    _In_ const sai_attribute_t *attr_list)
    {
        num_created_counter ++;
        return old_create_counter(counter_id, switch_id, attr_count, attr_list);
    }

    sai_status_t _ut_stub_remove_counter(_In_ sai_object_id_t counter_id)
    {
        num_created_counter --;
        return old_remove_counter(counter_id);
    }

    struct FlowcounterRouteOrchTest : public ::testing::Test
    {
        FlowcounterRouteOrchTest()
        {
            return;
        }

        void SetUp() override
        {
            ASSERT_EQ(sai_route_api, nullptr);
            map<string, string> profile = {
                { "SAI_VS_SWITCH_TYPE", "SAI_VS_SWITCH_TYPE_BCM56850" },
                { "KV_DEVICE_MAC_ADDRESS", "20:03:04:05:06:00" }
            };

            ut_helper::initSaiApi(profile);

            old_create_counter = sai_counter_api->create_counter;
            old_remove_counter = sai_counter_api->remove_counter;

            pold_sai_counter_api = sai_counter_api;
            ut_sai_counter_api = *sai_counter_api;
            sai_counter_api = &ut_sai_counter_api;

            // Mock sai API
            sai_counter_api->create_counter = _ut_stub_create_counter;
            sai_counter_api->remove_counter = _ut_stub_remove_counter;

            // Init switch and create dependencies
            m_app_db = make_shared<swss::DBConnector>("APPL_DB", 0);
            m_config_db = make_shared<swss::DBConnector>("CONFIG_DB", 0);
            m_state_db = make_shared<swss::DBConnector>("STATE_DB", 0);
            if(gMySwitchType == "voq")
                m_chassis_app_db = make_shared<swss::DBConnector>("CHASSIS_APP_DB", 0);

            sai_attribute_t attr;
            attr.id = SAI_SWITCH_ATTR_INIT_SWITCH;
            attr.value.booldata = true;

            auto status = sai_switch_api->create_switch(&gSwitchId, 1, &attr);
            ASSERT_EQ(status, SAI_STATUS_SUCCESS);

            // Get switch source MAC address
            attr.id = SAI_SWITCH_ATTR_SRC_MAC_ADDRESS;
            status = sai_switch_api->get_switch_attribute(gSwitchId, 1, &attr);

            ASSERT_EQ(status, SAI_STATUS_SUCCESS);

            gMacAddress = attr.value.mac;

            // Get the default virtual router ID
            attr.id = SAI_SWITCH_ATTR_DEFAULT_VIRTUAL_ROUTER_ID;
            status = sai_switch_api->get_switch_attribute(gSwitchId, 1, &attr);

            ASSERT_EQ(status, SAI_STATUS_SUCCESS);

            gVirtualRouterId = attr.value.oid;


            ASSERT_EQ(gCrmOrch, nullptr);
            gCrmOrch = new CrmOrch(m_config_db.get(), CFG_CRM_TABLE_NAME);

            TableConnector stateDbSwitchTable(m_state_db.get(), "SWITCH_CAPABILITY");
            TableConnector conf_asic_sensors(m_config_db.get(), CFG_ASIC_SENSORS_TABLE_NAME);
            TableConnector app_switch_table(m_app_db.get(),  APP_SWITCH_TABLE_NAME);

            vector<TableConnector> switch_tables = {
                conf_asic_sensors,
                app_switch_table
            };

            ASSERT_EQ(gSwitchOrch, nullptr);
            gSwitchOrch = new SwitchOrch(m_app_db.get(), switch_tables, stateDbSwitchTable);

            // Create dependencies ...
            TableConnector stateDbBfdSessionTable(m_state_db.get(), STATE_BFD_SESSION_TABLE_NAME);
            gBfdOrch = new BfdOrch(m_app_db.get(), APP_BFD_SESSION_TABLE_NAME, stateDbBfdSessionTable);

            const int portsorch_base_pri = 40;
            vector<table_name_with_pri_t> ports_tables = {
                { APP_PORT_TABLE_NAME, portsorch_base_pri + 5 },
                { APP_VLAN_TABLE_NAME, portsorch_base_pri + 2 },
                { APP_VLAN_MEMBER_TABLE_NAME, portsorch_base_pri },
                { APP_LAG_TABLE_NAME, portsorch_base_pri + 4 },
                { APP_LAG_MEMBER_TABLE_NAME, portsorch_base_pri }
            };

            vector<string> flex_counter_tables = {
                CFG_FLEX_COUNTER_TABLE_NAME
            };
            auto* flexCounterOrch = new FlexCounterOrch(m_config_db.get(), flex_counter_tables);
            gDirectory.set(flexCounterOrch);

            ASSERT_EQ(gPortsOrch, nullptr);
            gPortsOrch = new PortsOrch(m_app_db.get(), m_state_db.get(), ports_tables, m_chassis_app_db.get());
            gDirectory.set(gPortsOrch);

            vector<string> vnet_tables = {
                APP_VNET_RT_TABLE_NAME,
                APP_VNET_RT_TUNNEL_TABLE_NAME
            };

            vector<string> cfg_vnet_tables = {
                CFG_VNET_RT_TABLE_NAME,
                CFG_VNET_RT_TUNNEL_TABLE_NAME
            };

            auto* vnet_orch = new VNetOrch(m_app_db.get(), APP_VNET_TABLE_NAME);
            gDirectory.set(vnet_orch);
            auto* cfg_vnet_rt_orch = new VNetCfgRouteOrch(m_config_db.get(), m_app_db.get(), cfg_vnet_tables);
            gDirectory.set(cfg_vnet_rt_orch);
            auto* vnet_rt_orch = new VNetRouteOrch(m_app_db.get(), vnet_tables, vnet_orch);
            gDirectory.set(vnet_rt_orch);
            ASSERT_EQ(gVrfOrch, nullptr);
            gVrfOrch = new VRFOrch(m_app_db.get(), APP_VRF_TABLE_NAME, m_state_db.get(), STATE_VRF_OBJECT_TABLE_NAME);
            gDirectory.set(gVrfOrch);

            vector<table_name_with_pri_t> intf_tables = {
                { APP_INTF_TABLE_NAME,  IntfsOrch::intfsorch_pri},
                { APP_SAG_TABLE_NAME,   IntfsOrch::intfsorch_pri}
            };

            ASSERT_EQ(gIntfsOrch, nullptr);
            gIntfsOrch = new IntfsOrch(m_app_db.get(), intf_tables, gVrfOrch, m_chassis_app_db.get());

            const int fdborch_pri = 20;

            vector<table_name_with_pri_t> app_fdb_tables = {
                { APP_FDB_TABLE_NAME,        FdbOrch::fdborch_pri},
                { APP_VXLAN_FDB_TABLE_NAME,  FdbOrch::fdborch_pri},
                { APP_MCLAG_FDB_TABLE_NAME,  fdborch_pri}
            };

            TableConnector stateDbFdb(m_state_db.get(), STATE_FDB_TABLE_NAME);
            TableConnector stateMclagDbFdb(m_state_db.get(), STATE_MCLAG_REMOTE_FDB_TABLE_NAME);
            ASSERT_EQ(gFdbOrch, nullptr);
            gFdbOrch = new FdbOrch(m_app_db.get(), app_fdb_tables, stateDbFdb, stateMclagDbFdb, gPortsOrch);

            ASSERT_EQ(gNeighOrch, nullptr);
            gNeighOrch = new NeighOrch(m_app_db.get(), APP_NEIGH_TABLE_NAME, gIntfsOrch, gFdbOrch, gPortsOrch, m_chassis_app_db.get());

            auto* tunnel_decap_orch = new TunnelDecapOrch(m_app_db.get(), APP_TUNNEL_DECAP_TABLE_NAME);
            vector<string> mux_tables = {
                CFG_MUX_CABLE_TABLE_NAME,
                CFG_PEER_SWITCH_TABLE_NAME
            };
            auto* mux_orch = new MuxOrch(m_config_db.get(), mux_tables, tunnel_decap_orch, gNeighOrch, gFdbOrch);
            gDirectory.set(mux_orch);

            ASSERT_EQ(gFgNhgOrch, nullptr);
            const int fgnhgorch_pri = 15;

            vector<table_name_with_pri_t> fgnhg_tables = {
                { CFG_FG_NHG,                 fgnhgorch_pri },
                { CFG_FG_NHG_PREFIX,          fgnhgorch_pri },
                { CFG_FG_NHG_MEMBER,          fgnhgorch_pri }
            };
            gFgNhgOrch = new FgNhgOrch(m_config_db.get(), m_app_db.get(), m_state_db.get(), fgnhg_tables, gNeighOrch, gIntfsOrch, gVrfOrch);

            ASSERT_EQ(gSrv6Orch, nullptr);
            vector<string> srv6_tables = {
                APP_SRV6_SID_LIST_TABLE_NAME,
                APP_SRV6_MY_SID_TABLE_NAME
            };
            gSrv6Orch = new Srv6Orch(m_app_db.get(), srv6_tables, gSwitchOrch, gVrfOrch, gNeighOrch);

            // Start FlowCounterRouteOrch
            static const  vector<string> route_pattern_tables = {
                CFG_FLOW_COUNTER_ROUTE_PATTERN_TABLE_NAME,
            };
            gFlowCounterRouteOrch = new FlowCounterRouteOrch(m_config_db.get(), route_pattern_tables);

            ASSERT_EQ(gRouteOrch, nullptr);
            const int routeorch_pri = 5;
            vector<table_name_with_pri_t> route_tables = {
                { APP_ROUTE_TABLE_NAME,        routeorch_pri },
                { APP_LABEL_ROUTE_TABLE_NAME,  routeorch_pri }
            };
            gRouteOrch = new RouteOrch(m_app_db.get(), route_tables, gSwitchOrch, gNeighOrch, gIntfsOrch, gVrfOrch, gFgNhgOrch, gSrv6Orch);
            gNhgOrch = new NhgOrch(m_app_db.get(), APP_NEXTHOP_GROUP_TABLE_NAME);

            // Recreate buffer orch to read populated data
            vector<string> buffer_tables = { APP_BUFFER_POOL_TABLE_NAME,
                                             APP_BUFFER_PROFILE_TABLE_NAME,
                                             APP_BUFFER_QUEUE_TABLE_NAME,
                                             APP_BUFFER_PG_TABLE_NAME,
                                             APP_BUFFER_PORT_INGRESS_PROFILE_LIST_NAME,
                                             APP_BUFFER_PORT_EGRESS_PROFILE_LIST_NAME };

            gBufferOrch = new BufferOrch(m_app_db.get(), m_config_db.get(), m_state_db.get(), buffer_tables);

            Table portTable = Table(m_app_db.get(), APP_PORT_TABLE_NAME);

            // Get SAI default ports to populate DB
            auto ports = ut_helper::getInitialSaiPorts();

            // Populate pot table with SAI ports
            for (const auto &it : ports)
            {
                portTable.set(it.first, it.second);
            }

            // Set PortConfigDone
            portTable.set("PortConfigDone", { { "count", to_string(ports.size()) } });
            gPortsOrch->addExistingData(&portTable);
            static_cast<Orch *>(gPortsOrch)->doTask();

            portTable.set("PortInitDone", { { "lanes", "0" } });
            gPortsOrch->addExistingData(&portTable);
            static_cast<Orch *>(gPortsOrch)->doTask();

            // Prepare interface table
            Table intfTable = Table(m_app_db.get(), APP_INTF_TABLE_NAME);
            intfTable.set("Ethernet0", { {"NULL", "NULL" },
                                         {"mac_addr", "00:00:00:00:00:00" }});
            intfTable.set("Ethernet0:10.0.0.1/24", { { "scope", "global" },
                                                     { "family", "IPv4" }});
            gIntfsOrch->addExistingData(&intfTable);
            static_cast<Orch *>(gIntfsOrch)->doTask();

            // Prepare neighbor table
            Table neighborTable = Table(m_app_db.get(), APP_NEIGH_TABLE_NAME);

            map<string, string> neighborIp2Mac = {{"10.0.0.2", "00:00:0a:00:00:02" },
                                                  {"10.0.0.3", "00:00:0a:00:00:03" } };
            neighborTable.set("Ethernet0:10.0.0.2", { {"neigh", neighborIp2Mac["10.0.0.2"]},
                                                      {"family", "IPv4" }});
            neighborTable.set("Ethernet0:10.0.0.3", { {"neigh", neighborIp2Mac["10.0.0.3"]},
                                                      {"family", "IPv4" }});
            gNeighOrch->addExistingData(&neighborTable);
            static_cast<Orch *>(gNeighOrch)->doTask();

            //Prepare route table
            Table routeTable = Table(m_app_db.get(), APP_ROUTE_TABLE_NAME);
            routeTable.set("1.1.1.1/32", { {"ifname", "Ethernet0" },
                                           {"nexthop", "10.0.0.2" }});
            routeTable.set("0.0.0.0/0", { {"ifname", "Ethernet0" },
                                           {"nexthop", "10.0.0.2" }});
            gRouteOrch->addExistingData(&routeTable);
            static_cast<Orch *>(gRouteOrch)->doTask();

            // Enable flow counter
            std::deque<KeyOpFieldsValuesTuple> entries;
            entries.push_back({"FLOW_CNT_ROUTE", "SET", { {"FLEX_COUNTER_STATUS", "enable"}, {"POLL_INTERVAL", "10000"}}});
            auto consumer = dynamic_cast<Consumer *>(flexCounterOrch->getExecutor(CFG_FLEX_COUNTER_TABLE_NAME));
            consumer->addToSync(entries);
            static_cast<Orch *>(flexCounterOrch)->doTask();

            static_cast<Orch *>(gFlowCounterRouteOrch)->doTask();
            return;
        }

        void TearDown() override
        {
            gDirectory.m_values.clear();

            delete gCrmOrch;
            gCrmOrch = nullptr;

            delete gSwitchOrch;
            gSwitchOrch = nullptr;

            delete gBfdOrch;
            gBfdOrch = nullptr;

            delete gSrv6Orch;
            gSrv6Orch = nullptr;

            delete gNeighOrch;
            gNeighOrch = nullptr;

            delete gFdbOrch;
            gFdbOrch = nullptr;

            delete gPortsOrch;
            gPortsOrch = nullptr;

            delete gIntfsOrch;
            gIntfsOrch = nullptr;

            delete gFgNhgOrch;
            gFgNhgOrch = nullptr;

            delete gRouteOrch;
            gRouteOrch = nullptr;

            delete gNhgOrch;
            gNhgOrch = nullptr;

            delete gBufferOrch;
            gBufferOrch = nullptr;

            delete gVrfOrch;
            gVrfOrch = nullptr;

            delete gFlowCounterRouteOrch;
            gFlowCounterRouteOrch = nullptr;

            sai_counter_api = pold_sai_counter_api;
            ut_helper::uninitSaiApi();
            return;
        }
    };

    TEST_F(FlowcounterRouteOrchTest, FlowcounterRouteOrchTestPatternAddDel)
    {
         std::deque<KeyOpFieldsValuesTuple> entries;
        // Setting route pattern
        auto current_counter_num = num_created_counter;
        entries.push_back({"1.1.1.0/24", "SET", { {"max_match_count", "10"}}});
        auto consumer = dynamic_cast<Consumer *>(gFlowCounterRouteOrch->getExecutor(CFG_FLOW_COUNTER_ROUTE_PATTERN_TABLE_NAME));
        consumer->addToSync(entries);
        static_cast<Orch *>(gFlowCounterRouteOrch)->doTask();
        ASSERT_TRUE(num_created_counter - current_counter_num == 1);

        // Deleting route pattern
        current_counter_num = num_created_counter;
        entries.push_back({"1.1.1.0/24", "DEL", { {"max_match_count", "10"}}});
        consumer->addToSync(entries);
        static_cast<Orch *>(gFlowCounterRouteOrch)->doTask();
        ASSERT_TRUE(current_counter_num - num_created_counter == 1);

    }

    TEST_F(FlowcounterRouteOrchTest, DelayAddVRF)
    {
        std::deque<KeyOpFieldsValuesTuple> entries;
        // Setting route pattern with VRF does not exist
        auto current_counter_num = num_created_counter;
        entries.push_back({"Vrf1|1.1.1.0/24", "SET", { {"max_match_count", "10"}}});
        auto consumer = dynamic_cast<Consumer *>(gFlowCounterRouteOrch->getExecutor(CFG_FLOW_COUNTER_ROUTE_PATTERN_TABLE_NAME));
        consumer->addToSync(entries);
        static_cast<Orch *>(gFlowCounterRouteOrch)->doTask();
        ASSERT_TRUE(num_created_counter - current_counter_num == 0);

        // Create VRF
        entries.push_back({"Vrf1", "SET", { {"v4", "true"} }});
        auto vrf_consumer = dynamic_cast<Consumer *>(gVrfOrch->getExecutor(APP_VRF_TABLE_NAME));
        vrf_consumer->addToSync(entries);
        static_cast<Orch *>(gVrfOrch)->doTask();
        ASSERT_TRUE(num_created_counter - current_counter_num == 0);

        // Add route to VRF
        Table routeTable = Table(m_app_db.get(), APP_ROUTE_TABLE_NAME);
        routeTable.set("Vrf1:1.1.1.1/32", { {"ifname", "Ethernet0" },
                                            {"nexthop", "10.0.0.2" }});
        gRouteOrch->addExistingData(&routeTable);
        static_cast<Orch *>(gRouteOrch)->doTask();
        ASSERT_TRUE(num_created_counter - current_counter_num == 1);

        // Deleting route pattern
        current_counter_num = num_created_counter;
        entries.clear();
        entries.push_back({"Vrf1|1.1.1.0/24", "DEL", { {"max_match_count", "10"}}});
        consumer->addToSync(entries);
        static_cast<Orch *>(gFlowCounterRouteOrch)->doTask();
        ASSERT_TRUE(current_counter_num - num_created_counter == 1);

        // Deleting VRF
        entries.push_back({"Vrf1", "DEL", { {"v4", "true"} }});
        vrf_consumer->addToSync(entries);
        static_cast<Orch *>(gVrfOrch)->doTask();
    }
}
