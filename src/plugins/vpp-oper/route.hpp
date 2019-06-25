
#ifndef __OPER_ROUTE_H_
#define __OPER_ROUTE_H_

#include <vom/dump_cmd.hpp>
#include <vom/route.hpp>
#include <vom/prefix.hpp>
#include <vapi/ip.api.vapi.hpp>

class route_dump : public VOM::dump_cmd<vapi::Ip_route_dump>
{
public:
  /**
   * Constructor
   */
  route_dump(VOM::route::table_id_t id, const VOM::l3_proto_t& proto);

  /**
   * Issue the command to VPP/HW
   */
  VOM::rc_t issue(VOM::connection& con);

  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;

private:
  /**
   * HW reutrn code
   */
  VOM::HW::item<bool> item;
  VOM::route::table_id_t m_id;
  const VOM::l3_proto_t& m_proto;
};


#endif // __OPER_ROUTE_H_
