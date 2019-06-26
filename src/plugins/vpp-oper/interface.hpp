#ifndef __OPER_INTERFACE_H_
#define __OPER_INTERFACE_H_

#include <vom/dump_cmd.hpp>
#include <vapi/interface.api.vapi.hpp>

class interface_dump : public VOM::dump_cmd<vapi::Sw_interface_dump>
{
public:
  /**
   * Default Constructor
   */
  interface_dump();

  /**
   * Issue the command to VPP/HW
   */
  VOM::rc_t issue(VOM::connection& con);
  /**
   * convert to string format for debug purposes
   */
  std::string to_string() const;
};

#endif //__OPER_INTERFACE_H_
