from pygdbmi.gdbcontroller import GdbController
from pprint import pprint
import re
import copy
from pwn import *
class GdbWrapper():
    _COLORS = {}
    Maps=[]
    def __init__(self, pid):
        self.pid = pid
    def _attach(self):
        self.gdbmi = GdbController()
        init_cmds = ["set exception-verbose on",
                     "source ~/.gdbinit",
                     "set print element 0",
                     "attach {}".format(str(self.pid)),
                     "set charset ASCII"]
        for cmd in init_cmds:
            self.gdbmi.write(cmd)
    def _detach(self):
        self.gdbmi.exit()
    def exec_cmds(self, cmds, parsed = False): #cmd( str ) and cmds( [] ) are both supported
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
            if parsed == False:
                return ret[0]
            try:
                toparse = copy.copy(ret)
                parsed_ret = self._parse_all(toparse[0])
                if type(parsed_ret).__name__ == "list" and len(parsed_ret) == 1:
                    return parsed_ret[0]
                return parsed_ret
            except Exception,e:
                pass
        else:
            if parsed == False:
                return ret
            try:
                toparse = copy.copy(ret)
                parsed_list = []
                for one_ret in toparse:
                    parsed_ret = self._parse_all(one_ret)
                    if type(parsed_ret).__name__ == "list" and len(parsed_ret) == 1:
                        parsed_ret = parsed_ret[0]
                    parsed_list.append(parsed_ret)
                return parsed_list
            except Exception,e:
                pass
    def _parse_single(self, single):
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
    def _parse_all(self, key_values):
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
                    elif key_values[x] == "}":
                        if len(index) > 1:
                            index.pop(-1)
                            continue
                        else:
                            left = index[-1]
                            index.pop(-1)
                            right = x
                            deeper = copy.copy(key_values)
                            deeper = deeper[left + 1: right]
                            value = self._parse_all(deeper)
                            name_left = left - 1
                            name_right = left
                            while name_left > 0:
                                if key_values[name_left] == '=':
                                    name_right = name_left
                                if name_left == 0:
                                    break
                                if key_values[name_left] == ',' or key_values[name_left] == '{':
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
                parsed_ret = dict(parsed_ret.items() + self._parse_all(key_values).items())
            return parsed_ret
        elif "{" not in key_values and "}"  not in key_values:
            is_dict = False
            parsed = []
            singles = key_values.split(",")
            if "" in singles:
                singles.remove("")
            for single in singles:
                single_parse = self._parse_single(single)
                parsed.append(single_parse)
            for x in parsed:
                if type(x).__name__ == "dict":
                    is_dict = True
            if is_dict == True:
                dict_ret = {}
                for x in parsed:
                    if type(x).__name__ == "dict":
                        dict_ret = dict(dict_ret.items() + x.items())
                    elif x != '':
                        dict_ret = dict(dict_ret.items() + {x: x}.items())
                return dict_ret
            else:
                return parsed
    def get_value(self, arg_name = "", address = None):
        if arg_name != "":
            exec_ret = self.exec_cmds("p {}".format(arg_name))
            exec_ret = arg_name + exec_ret[exec_ret.find("="):]
            exec_ret = self._parse_all(exec_ret)
            return exec_ret
        elif address != None:
            exec_ret = self.exec_cmds("p *{}".format(hex(address).replace("L","")))
            exec_ret = hex(address).replace("L","") + exec_ret[exec_ret.find("="):]
            exec_ret = self._parse_all(exec_ret)
            return exec_ret
    def vmmap(self):
        raw_output = self.exec_cmds("vmmap").split("\n")
        #get STACK_COLOR
        self._COLORS["STACK"] = copy.copy(raw_output[0][raw_output[0].find("STACK") - 6 : raw_output[0].find("STACK")]).strip()
        self._COLORS["HEAP"] = copy.copy(raw_output[0][raw_output[0].find("HEAP") - 6 : raw_output[0].find("HEAP")]).strip()
        self._COLORS["CODE"] = copy.copy(raw_output[0][raw_output[0].find("CODE") - 6 : raw_output[0].find("CODE")]).strip()
        self._COLORS["DATA"] = copy.copy(raw_output[0][raw_output[0].find("DATA") - 6 : raw_output[0].find("DATA")]).strip()
        self._COLORS["RWX"] = copy.copy(raw_output[0][raw_output[0].find("RWX") - 6 : raw_output[0].find("RWX")]).strip()
        self._COLORS["RODATA"] = copy.copy(raw_output[0][raw_output[0].find("RODATA") - 6 : raw_output[0].find("RODATA")]).strip()
        self._COLORS["RESET"] = copy.copy(raw_output[0][raw_output[0].find("STACK") + 5 : raw_output[0].find("STACK") + 10]).strip()
        raw_output = raw_output[1:]
        for line in raw_output:
            line = line.strip()
            if len(line) == 0:
                continue
            map_node = {}
            for key,value in self._COLORS.items():
                if value in line and key != "RESET" :
                    map_node["TYPE"] = key
                    if key != "RODATA":
                        break
            line = line.replace(self._COLORS[map_node["TYPE"]],"")
            try:
                line = line.replace(self._COLORS["RESET"], "")
            except Exception,e:
                pass
            try:
                line = line.split(" ")
                while '' in line:
                    line.remove('')
            except Exception,e:
                pass
            if len(line) > 0:
                map_node["start"] = int(line[0], 16)
                map_node["end"] = int(line[1], 16)
                map_node["flag"] = line[2]
                map_node["len"] = int("0x" +line[3], 16)
                try:
                    map_node["path"] = line[5]
                except:
                    map_node["path"] = ""
                self.Maps.append(map_node)
        return self.Maps
