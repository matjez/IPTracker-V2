import os
import threading
import subprocess
import time
import csv
import json
import netifaces
import winreg as wr
import tkinter.ttk as ttk
import tkinter as tk

from datetime import datetime
from tkinter import Tk, Label, Button, Entry, W, StringVar
from netaddr import IPNetwork


class IPTracker:

    def __init__(self, master):
        """ Creating global variables and frames. """

        self._FINISH = False
        self._FINISH_SEARCHING = False
        self.hosts_searching_thread = None

        self.assigned_devices = []
        self.devices_to_track = set()
        self.network_cards = set()
        self.devices_frames = []
        self.devices_frames_buttons = {}
        self.settings_dict = {}

        self.load_settings()

        self.root = master
        self.root.title("IP Tracker")
        self.root.minsize(500, 700)
        self.root.maxsize(500, 700)

        self.network_cards = self.search_interfaces()
        self.selected_netcard = self.network_cards[0]["Name"]
        self.assigned_devices = self.get_ip_list()

        self.generate_window()
        self.select_netcard(None, self.network_cards[0]["Name"])

        self.refresh_searching()

    def generate_window(self):
        """Generate main GUI window. """

        # Frames

        self.master = tk.Frame(self.root, width='500', height='700')
        self.frame1 = tk.Frame(self.master)
        self.frame2 = tk.Frame(self.master)
        self.frame3 = tk.Frame(self.master)
        self.frame4 = tk.Frame(self.master, width='500', height='10', highlightthickness=10)

        # Frames layout

        self.master.pack(anchor="nw", fill="both", expand=True)

        self.frame1.pack(anchor="nw", fill="x", expand=False)
        self.frame2.pack(anchor="nw", fill="x", expand=False)
        self.frame3.pack(anchor="nw", fill="x", expand=False)
        self.frame4.pack(anchor="nw", fill="both", expand=True)

        self.canvas = tk.Canvas(self.frame4)
        self.scrollbar = ttk.Scrollbar(self.frame4, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)
        self.scrollable_frame.pack(anchor="nw", fill="both", expand=True)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.frame4.config(highlightbackground="SystemButtonFace", highlightcolor="SystemButtonFace")
        self.myscrollbar = ttk.Scrollbar(self.frame4, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.myscrollbar.set, bg="white")

        self.frame4.pack()
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Frame 1

        self.top_label = Label(self.frame1, text="Devices tracker", font=("", 12))

        # layout 1

        self.top_label.pack(pady=3)

        # Frame 2

        self.frame2.grid_rowconfigure(3, weight=1)
        self.frame2.grid_columnconfigure(6, weight=1)

        self.drop_list = Label(self.frame2, text="Network card:")

        self.netcards_value = StringVar()
        self.combobox = ttk.Combobox(self.frame2, textvariable=self.netcards_value)
        self.combobox['values'] = [i["Name"] for i in self.network_cards]
        self.combobox.current(0)
        self.combobox.bind("<<ComboboxSelected>>", self.select_netcard)

        self.settings = Button(self.frame2, text="Settings", width=6, command=self.create_settings_window)
        vcmd = self.root.register(self.validate)

        # layout 2

        self.drop_list.grid(row=0, column=0, sticky=W)
        self.combobox.grid(row=0, column=1, sticky=W)
        self.settings.grid(row=0, column=7, sticky=W)

        # Frame 3

        self.ip_address_label = Label(self.frame3, text="Add IP address:")

        self.custom_ip_1 = Entry(self.frame3, validate="key", validatecommand=(vcmd, '%P'), width=4)
        self.custom_ip_2 = Entry(self.frame3, validate="key", validatecommand=(vcmd, '%P'), width=4)
        self.custom_ip_3 = Entry(self.frame3, validate="key", validatecommand=(vcmd, '%P'), width=4)
        self.custom_ip_4 = Entry(self.frame3, validate="key", validatecommand=(vcmd, '%P'), width=4)

        self.add_ip_button = Button(self.frame3, text="Add", command=self.get_address_ip_from_user)

        self.search_devices_button = Button(self.frame3, text="Search for devices",
                                            command=lambda: self.change_search_button_on())
        self.run_tracking_button = Button(self.frame3, text="Run tracking", command=lambda: self.track())

        # layout 3

        self.ip_address_label.grid(row=0, column=0, sticky=W)
        self.custom_ip_1.grid(row=0, column=1, sticky=W)
        self.custom_ip_2.grid(row=0, column=2, sticky=W)
        self.custom_ip_3.grid(row=0, column=3, sticky=W)
        self.custom_ip_4.grid(row=0, column=4, sticky=W)
        self.add_ip_button.grid(row=0, column=5, sticky=W, padx=2)
        self.search_devices_button.grid(row=0, column=7, sticky=W, padx=2)
        self.run_tracking_button.grid(row=0, column=9, padx=2)

    def load_settings(self):
        """ Reading settings from settings.txt """

        with open("settings.txt", "r") as f:
            f = f.readlines()
            for line in f:
                if len(line) > 0:
                    line = line.replace("\n", "")
                    line = line.split("=")    
                    self.settings_dict[line[0]] = line[1]

    def save_settings(self, new_settings):
        """ Changing settings in settings.txt """

        if len(new_settings) > 0:
            for i in new_settings.keys():
                self.settings_dict[i] = new_settings[i]
        
        with open("settings.txt", "w") as f:
            wrt = ""
            for i in self.settings_dict.keys():
                wrt += i + "=" + self.settings_dict[i] + "\n"
            f.write(wrt)
        self.load_settings()

    def get_ip_list(self):
        """ Reading ip list for network card from devices.json. """

        ret = []

        try:
            with open("devices.json") as f:
                devices_in_network = json.load(f)

                devices_in_network_keys = list(devices_in_network.keys())

                if type(self.selected_netcard) == str:
                    return []

                if not self.selected_netcard["Name"] in devices_in_network_keys:

                    devices_in_network[self.selected_netcard["Name"]] = []
                    with open("devices.json", "w") as f:
                        json.dump(devices_in_network, f)

                for line in devices_in_network[self.selected_netcard["Name"]]:
                    line = line.replace("\n", "")

                    splitted = line.split(".")
                    correct = True

                    try:
                        length = 0
                        for i in splitted:
                            if not len(i) < 1 and not len(i) > 3 and int(i) <= 255 and int(i) >= 0:
                                correct = True
                                length += 1
                            else:
                                correct = False
                                break

                        if length == 4 and correct == True and line not in ret:
                            ret.append(line)
                    except:
                        pass
        except:
            ret = []

        return ret

    def add_ip(self, ip_address):
        """ Adding ip received from user."""

        if ip_address not in self.assigned_devices:
            self.insert_device(self.selected_netcard, ip_address)
            self.assigned_devices.append(ip_address)
            self.refresh_searching()

    def __write_line(self,status):
        """ Write line of data(Date,time,status) in each file. """

        with open(self.path, "a", newline='') as self.f:
            self.writer = csv.writer(self.f, delimiter="\t")
            self.writer.writerow([str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")) + " " + status])   
            return     

    def _get_card_name_from_reg(self, iface_guids):
        """ Getting network card name from regedit. """

        iface_names = ['(unknown)' for i in range(len(iface_guids))]
        reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
        reg_key = wr.OpenKey(reg, r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
        for i in range(len(iface_guids)):
            try:
                reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r'\Connection')
                iface_names[i] = wr.QueryValueEx(reg_subkey, 'Name')[0]
            except FileNotFoundError:
                pass
        return iface_names

    def search_interfaces(self):
        """ Searching for network cards on local machine. """

        self.network_cards = []
        for i in netifaces.interfaces():
            tmp = {}
            try:
                tmp["Name"] = self._get_card_name_from_reg([i])[0]
                if not tmp["Name"] == "(unknown)":
              
                    tmp["IP Address"] = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['addr']
                    tmp["Mask"] = netifaces.ifaddresses(i)[netifaces.AF_INET][0]['netmask']
                    tmp["Gateway"] = netifaces.gateways()['default'][netifaces.AF_INET][0]

                    self.network_cards.append(tmp)
            except:
                pass

        return self.network_cards
    
    def _start_searching(self, network_card):
        """ Starts searching for new network cards. """

        network = IPNetwork('/'.join([network_card["Gateway"], network_card["Mask"]]))
        generator = network.iter_hosts()

        for i in generator:

            i = str(i)
            if self._FINISH_SEARCHING:
                self.change_search_button_off(True,False)
                break
            else:
                if not i in self.assigned_devices and not i == network_card["IP Address"]:

                    response = subprocess.Popen('ping -n 1 {}'.format(i), stdout = subprocess.PIPE).communicate()[0]
                
                    if "unreachable" in str(response) or "Request timed out" in str(response):
                        pass
                    else:
                        self.insert_device(self.selected_netcard,i)
                        self.assigned_devices.append(i)
                        self.refresh_searching()
                else:
                    pass

        self._FINISH_SEARCHING = False
        self.change_search_button_off(True,False)
        return

    def search_new_hosts(self, name):
        """ Starts thread for host searching. """

        for interface in self.network_cards:
            if interface["Name"] == name["Name"]:
                self.hosts_searching_thread = threading.Thread(target=self._start_searching,args=(interface,))
                self.hosts_searching_thread.start()

                break

    def stop_searching(self):
        """ Changing flag _FINISH_SEARCHING to true and stopping current searching thread. """
        self._FINISH_SEARCHING = True
        
    def _run_tracking(self,interval):
        """ Run tracking devices in self.devices_to_track. """

        while True:
            if len(self.devices_to_track) > 0:
                for hostname in self.devices_to_track.copy():
                    if hostname in self.devices_to_track:
                        self.response = subprocess.Popen('ping -n 1 {}'.format(hostname),stdout = subprocess.PIPE).communicate()[0]
                        if not os.path.exists("data/"+self.selected_netcard["Name"]):
                            os.makedirs("data/"+self.selected_netcard["Name"])

                        self.path = "data/{}/{}.csv".format(self.selected_netcard["Name"],hostname)
                        
                        if "unreachable" in str(self.response) or "Request timed out" in str(self.response):
                            if os.path.exists(self.path):
                                self.__write_line("0") 
                            else:
                                self.__write_line("0")
                        else:
                            if os.path.exists(self.path):
                                self.__write_line("1") 
                            else:
                                self.__write_line("1")

                        self.check_status(self.path, hostname)

            if interval <= 0:
                interval = 1

            for i in range(interval):

                if self._FINISH:
                    self.run_tracking_button = Button(self.frame3, text="Run tracking", command=lambda: self.track())
                    self.run_tracking_button.grid(row=0, column=9) 
                    self._FINISH = False
                    for key in self.devices_frames_buttons.keys():
                        if "start" in key:
                            self.devices_frames_buttons[key][2].configure(background="SystemButtonFace", text="N/A")
                    return
                time.sleep(1)

    def add_device_to_track(self, data):
        """ Adding device to self.devices_to_track. """

        self.devices_to_track.add(data[1])
        self.devices_frames_buttons[data[0]][1] = ttk.Button(data[2], text='Stop',command=lambda c=[data[0], data[1], data[2]]: self.remove_device_to_track(c))
        self.devices_frames_buttons[data[0]][1].grid(row=int(data[0][-1]), column=2,padx=5) 

    def remove_device_to_track(self, data):
        """ Removing device from self.devices_to_track. """

        self.devices_to_track.remove(data[1])
        self.devices_frames_buttons[data[0]][1] = ttk.Button(data[2], text='Start', command=lambda c=[data[0], data[1], data[2]]: self.add_device_to_track(c))
        self.devices_frames_buttons[data[0]][1].grid(row=int(data[0][-1]), column=2, padx=5)

        if len(self.devices_to_track) == 0:
            for key in self.devices_frames_buttons.keys():
                if "start" in key and self.devices_frames_buttons[key][0] not in self.devices_to_track:
                    self.devices_frames_buttons[key][2].configure(background="SystemButtonFace", text="N/A")

    def insert_device(self,net_card,ip_address):
        """ Inserting device to devices.json. """

        with open('devices.json') as f:
            data = json.load(f)          

        try:
            data[net_card["Name"]].append(ip_address)
        except:
            data[net_card["Name"]] = [ip_address]

        with open('devices.json', 'w') as f:
            json.dump(data, f)

    def track(self):
        """ Starts devices tracking thread and change name of button to 'Stop tracking' """

        try:
            interval = int(self.settings_dict["interval"])
            if interval == 0:
                interval = 1
        except:
            interval = 1

        self._FINISH = False
        self.t = threading.Thread(target=self._run_tracking, args=(interval,))
        self.t.start()
        self.run_tracking_button = Button(self.frame3, text="Stop tracking", command=lambda: self.turn_off_tracking())
        self.run_tracking_button.grid(row=0, column=9) 

    def turn_off_tracking(self):
        """ Changing flag self._FINISH to True and stopping tracking. """

        self._FINISH = True

    def check_status(self,path,hostname):
        """ Checking status of last line in file('current_ip'.csv). If status is 1 display 'ON', if 0 display 'OFF', if not device is not currently tracked display 'N/A' """

        with open(path, 'r') as f:
            
            line =list(csv.reader(f, delimiter=' '))
            for key in self.devices_frames_buttons.keys():
                if self.devices_frames_buttons[key][0] == hostname and "start" in key:
                    if line[-1][2] == "1":
                        self.devices_frames_buttons[key][2].configure(background="green", text="ON")
                    else:
                        self.devices_frames_buttons[key][2].configure(background="red", text="OFF")
                elif "start" in key and self.devices_frames_buttons[key][0] not in self.devices_to_track:
                    self.devices_frames_buttons[key][2].configure(background="SystemButtonFace", text="N/A")

    def create_settings_window(self):
        """ Opens window with general settings to change.  """

        self.settings_window = tk.Toplevel(self.master)
        self.settings_window.title("Settings")
        self.settings_window.minsize(200,50)
        self.settings_window.maxsize(200,200)
        vcmd = self.settings_window.register(self.validate_interval)

        empty_space1 = Label(self.settings_window, text="")
        empty_space1.grid(row=0, column=0)
            
        Label(self.settings_window, text="Interval [s]",font=("",)).grid(row=1, column=0)
        val = StringVar()
        interval_value = Entry(self.settings_window, textvariable=val, validate="key",validatecommand=(vcmd, '%P'),width=3)
        interval_value.grid(row=1, column=1)

        empty_space2 = Label(self.settings_window, text="")
        empty_space2.grid(row=2, column=0)
        
        confirm_button = Button(self.settings_window,text="Confirm",command=lambda : self.save_settings({"interval": interval_value.get()}))
        confirm_button.grid(row=3, column=1)
        
    def change_search_button_on(self):
        """ If clicked 'Search for devices' button changes it's text to 'Stop searching' """

        self.search_devices_button.destroy()
        self.stop_search_devices_button = Button(self.frame3,text="Stop searching",command=lambda: self.change_search_button_off(False, True))
        self.stop_search_devices_button.grid(row=0, column=7, sticky=W) 
        self.search_new_hosts(self.selected_netcard)
      
    def change_search_button_off(self, button, stop):
        """ If clicked 'Stop searching' button changes it's text to 'Search for devices' """

        def change_button():
            self.search_devices_button.destroy()
            self.search_devices_button = Button(self.frame3,text="Search for devices",command=lambda: self.change_search_button_on())
            self.search_devices_button.grid(row=0, column=7, sticky=W) 
        def stop_search_button():
            self.stop_searching()

        if stop:
            stop_search_button()
        if button:
            self.search_devices_button.destroy()
            change_button()

    def clear_history(self, ip):
        """ Clearing file which contain data from device tracking.  """

        path = "data/{}/{}.csv".format(self.selected_netcard["Name"], ip)
        with open(path, "w") as f:
            f.write("")       
    
    def select_netcard(self, event, netcard=""):
        """ If clicked network card name from list chosen one is assigned to current self.selected_network_card. """

        self._FINISH = True

        if len(netcard) > 0:
            netcard = netcard
        else:
            netcard = self.combobox.get()

        for card in self.network_cards:
            if card["Name"] == netcard:
                self.selected_netcard = card
                break

        for device in self.devices_frames:
            device.destroy()

        self.devices_frames.clear()
        self.assigned_devices.clear()
        self.devices_frames_buttons.clear()

        self.assigned_devices = self.get_ip_list()

        self.refresh_searching()

    def delete_ip_frame(self, ip_address):
        """ Removes ip from self.assigned_devices and deletes it's frame. """

        self.assigned_devices.remove(ip_address)

        with open("devices.json") as f:
            devices_in_network = json.load(f)

            devices_in_network[self.selected_netcard["Name"]] = self.assigned_devices

            with open("devices.json", "w") as f:
                json.dump(devices_in_network, f)
        self.refresh_searching()

    def refresh_searching(self):
        try:
            n = 0
            for i in self.devices_frames:
                self.devices_frames[n].destroy()
                n += 1
        except:
            pass
        i = 0
        try:
            self.devices_frames_buttons.clear()
            for ip in self.assigned_devices:
                tmp = tk.Frame(self.scrollable_frame, borderwidth=2, relief="groove")
                tmp.grid(row=i, column=0, pady=5, padx=2)
                tmp.grid_columnconfigure(1, weight=1)
                tmp.configure(background='white')

                text = "{}".format(str(ip))

                tmp_label = ttk.Label(tmp, text=text, font=("Arial", 16), width=13)
                tmp_label.configure(background='white')
                tmp_label.grid(row=i, column=0)
                
                start = "start_" + str(i)
                options = "options_" + str(i)

                self.devices_frames_buttons[start] = []
                self.devices_frames_buttons[start].append(text)

                if text in self.devices_to_track:
                    self.devices_frames_buttons[start].append(ttk.Button(tmp, text='Stop', command=lambda c=[start, self.devices_frames_buttons[start][0], tmp]: self.remove_device_to_track(c)))
                    self.devices_frames_buttons[start][1].grid(row=i, column=2, padx=5)

                else:
                    self.devices_frames_buttons[start].append(ttk.Button(tmp, text='Start',command=lambda c=[start, self.devices_frames_buttons[start][0], tmp]: self.add_device_to_track(c)))

                    self.devices_frames_buttons[start][1].grid(row=i, column=2, padx=5)

                self.devices_frames_buttons[start].append(ttk.Label(tmp, text='N/A'))
                self.devices_frames_buttons[start][2].grid(row=i, column=1, padx=5)
                self.devices_frames_buttons[start].append(ttk.Button(tmp, text='Clear history', command=lambda c=self.devices_frames_buttons[start][0]: self.clear_history(c)))
                self.devices_frames_buttons[start][3].grid(row=i, column=3, padx=5)


                self.devices_frames_buttons[options] = []
                self.devices_frames_buttons[options].append(text)
                self.devices_frames_buttons[options].append(ttk.Button(tmp,
                                                                       text='Delete',
                                                                       command=lambda c=self.devices_frames_buttons[start][0]: self.delete_ip_frame(c)))

                self.devices_frames_buttons[options][1].grid(row=i, column=4, padx=5)

                if tmp not in self.devices_frames:
                    self.devices_frames.append(tmp)

                i += 1

        except:
            pass

    def get_address_ip_from_user(self):
        """ Gettings ip from user entry and calling function which insert ip in file. """
        
        ip1 = self.custom_ip_1.get()
        ip2 = self.custom_ip_2.get()
        ip3 = self.custom_ip_3.get()
        ip4 = self.custom_ip_4.get()

        splitted = [ip1, ip2, ip3, ip4]
        address = ".".join(splitted)

        try:
            length = 0
            for i in splitted:
                correct = True
                if not len(i) < 1 and not len(i) > 3 and int(i) <= 255 and int(i) >= 0:
                    correct = True
                    length += 1
                else:
                    correct = False
                    break

            if length == 4 and correct and address not in self.assigned_devices:
                self.assigned_devices.append(address)
                self.insert_device(self.selected_netcard,address)
                self.refresh_searching()
            
        except:
            pass

    def validate(self, new_text):
        """ Validation when pressed key. Allows only numbers not bigger than 3 digits. """

        if len(new_text) > 3:
            return False

        if not new_text: # the field is being cleared
            self.entered_number = 0
            return True


        try:
            self.entered_number = int(new_text)
            return True

        except ValueError:
            return False        

    def validate_interval(self, new_value):
        """ Validation when pressed key.
        Allows only numbers not bigger than 2 digits. 
        """

        if len(new_value) > 2:
            return False

        if not new_value: # the field is being cleared
            return True

        try:
            self.entered_number = int(new_value)
            return True

        except ValueError:
            return False

    def _on_mousewheel(self, event):
        """IF scroll wheeled set position of slider."""

        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")


root = Tk()
my_gui = IPTracker(root)
root.mainloop()
