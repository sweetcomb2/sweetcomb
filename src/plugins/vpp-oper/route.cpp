
#include "route.hpp"

using namespace VOM;

route_dump::route_dump(route::table_id_t id, const l3_proto_t& proto)
  : m_id(id)
  , m_proto(proto)
{
}

std::string
route_dump::to_string() const
{
  return ("ip-route-dump");
}

rc_t
route_dump::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  auto& payload = m_dump->get_request().get_payload();

  payload.table.table_id = m_id;
  payload.table.is_ip6 = m_proto.is_ipv6();

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}
