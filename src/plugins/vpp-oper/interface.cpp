#include "interface.hpp"

using namespace VOM;

interface_dump::interface_dump()
{
}

rc_t
interface_dump::issue(connection& con)
{
  m_dump.reset(new msg_t(con.ctx(), std::ref(*this)));

  auto& payload = m_dump->get_request().get_payload();
  payload.name_filter_valid = 0;

  VAPI_CALL(m_dump->execute());

  wait();

  return rc_t::OK;
}

std::string
interface_dump::to_string() const
{
  return ("itf-dump");
}
