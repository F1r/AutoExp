from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import re
import copy
class GdbWrapper():
    def __init__(self, pid):
        self.pid = pid
    def _attach(self):
        self.gdbmi = GdbController()
        init_cmds = ["attach {}".format(str(self.pid)), "source ~/.gdbinit", "set print element 0",
                     "set exception-verbose on"]
        for cmd in init_cmds:
            self.gdbmi.write(cmd)
    def _detach(self):
        self.gdbmi.exit()
    def exec_cmds(self, cmds): #cmd( str ) and cmds( [] ) are both supported
        self._attach()
        if type(cmds).__name__ == "str":
            cmds = [cmds]
        ret = []
        for cmd in cmds:
            start_ret = False
            cmd_ret = ""
            for x in self.gdbmi.write(cmd):
                if type(x["payload"]).__name__ == 'unicode':
                    if start_ret == True:
                        cmd_ret += (x["payload"].encode("unicode-escape").decode("unicode-escape").encode("ascii"))
                    try:
                        if cmd in x["payload"].encode("unicode-escape").decode("unicode-escape").encode("ascii"):
                            start_ret = True
                    except:
                        pass
                elif type(x["payload"]).__name__ == 'str':
                    if start_ret == True:
                        cmd_ret += (x["payload"])
                    try:
                        if cmd in x["payload"]:
                            start_ret = True
                    except:
                        pass
            ret.append(cmd_ret.replace("\\n", "\n"))
        self._detach()
        if len(ret) == 1:
            return ret[0]
        return ret
    def parse_single(self, single):
        if "=" in single:
            single = re.sub("\(.*?\)|\<.*?\>", "", single).strip().replace(" ", "").split("=")
            if single[-1].startswith("0x") or single[-1].startswith("0X"):
                single[-1] = int(single[-1], 16)
            elif single[-1].isalnum():
                single[-1] = int(single[-1])
            else:
                single[-1] = str(single[-1])
            return {single[0]:single[-1]}
        else:
            if single.startswith("0x") or single.startswith("0X"):
                single = int(single, 16)
            elif single.isalnum():
                single = int(single)
            else:
                single = str(single)
            return single
    def parse_all(self, key_values):
        key_values = key_values.replace(" ", "").replace("\n", "")
        key_values = re.sub("\(.*?\)|\<.*?\>", "", key_values)
        key_values = key_values.replace("\\\\","\\").replace("\\\"", "\"")
        parsed_list = []
        if "{" in key_values and "}" in key_values:
            index = []
            while "{" in key_values and "}" in key_values:
                for x in range(0, len(key_values)):
                    if key_values[x] == "{":
                        index.append(x)
                    elif key_values[x] =="}":
                        if len(index) >1:
                            index.pop(-1)
                            continue
                        else:
                            left = index[-1]
                            index.pop(-1)
                            right = x
                            deeper = copy.copy(key_values)
                            deeper = deeper[left + 1: right]
                            value = self.parse_all(deeper)
                            name_left = left
                            name_right = left
                            while name_left > 0:
                                if key_values[name_left] == "=":
                                    name_right = name_left
                                if name_left == 0:
                                    break
                                if name_left == "," or name_left == "{":
                                    name_left += 1
                                    break
                                name_left -= 1
                            name = key_values[name_left: name_right]
                            parsed_list.append({name: value})
                            key_values = key_values[:name_left] + key_values[right + 1:]
                            break
            parsed_ret = {}
            for dict_node in parsed_list:
                parsed_ret = dict(parsed_ret.items() + dict_node.items())
            if len(key_values.strip().replace(" ", "")) > 0:
                parsed_ret = dict(parsed_ret.items() + self.parse_all(key_values).items())
            return parsed_ret
        elif "{" not in key_values and "}"  not in key_values:
            is_dict = False
            parsed = []
            singles = key_values.split(",")
            if "" in singles:
                singles.remove("")
            for single in singles:
                single_parse = self.parse_single(single)
                parsed.append(single_parse)
            for x in parsed:
                if type(x).__name__ == "dict":
                    is_dict = True
            if is_dict == True:
                dict_ret = {}
                for x in parsed:
                    if type(x).__name__ == "dict":
                        dict_ret = dict(dict_ret.items() + x.items())
                    else:
                        dict_ret = dict(dict_ret.items() + {x: x}.items())
                return dict_ret
            else:
                return parsed
    def get_value(self, arg_name = "", address = None):
        if arg_name != "":
            exec_ret = self.exec_cmds("p {}".format(arg_name))
            exec_ret = arg_name + exec_ret[exec_ret.find("="):]
            exec_ret = self.parse_all(exec_ret)
            return exec_ret
        elif address != None:
            exec_ret = self.exec_cmds("p *{}".format(hex(address).replace("L","")))
            exec_ret = hex(address).replace("L","") + exec_ret[exec_ret.find("="):]
            exec_ret = self.parse_all(exec_ret)
            return exec_ret
