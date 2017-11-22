import logging
from apps import App, event, action
from apps.OpenVAS.pvsl import Client, exceptions
from datetime import datetime
import subprocess

# from apps.OpenVAS.events import pull_down

logger = logging.getLogger(__name__)


class OpenVAS(App):
    """
       An app to interface with a running OpenVAS manager.
    """

    def __init__(self, name=None, device=None):
        App.__init__(self, name, device)
        self.h = self.device_fields['host']
        self.u = self.device_fields['username']
        self.p = self.device_fields['port']

    @action
    def app_create_port_list(self, name, port_range, comment=None):
        """
        Create a port list from range(s) of ports
        :param name: Name of the port range
        :param port_range: Port range (comma separated values, e.g. T:100-200,T:300-400,U:800-900
        :param comment: (Optional) Comment to add
        :return: uuid of the created list
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                r = cli.create_port_list(name, port_range=port_range, comment=comment)
                return r.data['@id']
        except exceptions.HTTPError:
            return False, "BadPorts"
        except exceptions.ElementExists:
            return False, "AlreadyExists"
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_create_target(self, name, hosts, port_list=None, comment=None):
        """
        Creates a new target
        :param name: Name of the new target
        :param hosts: Comma separated list of hosts
        :param port_list: (Optional) uuid of the port list to use
        :param comment: (Optional) Comment to add
        :return: uuid of the created target
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                r = cli.create_target(name, hosts, port_list=port_list, comment=comment)
                return r.data['@id']
        except exceptions.ElementNotFound:
            return False, "InvalidUUID"
        except exceptions.ElementExists:
            return False, "AlreadyExists"
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_create_schedule(self, name, comment=None, first_time=None, duration=None, duration_unit=None, period=None,
                            period_unit=None, utc_offset=None):
        """
        Creates a new schedule
        :param name: Name of the schedule
        :param comment: (Optional) Comment to add
        :param first_time: (Optional) First time to run the task, in the format "MM/DD/YYYY HH:MM _M" (12h)
        :param duration: (Optional) How long to run task before it is aborted
        :param duration_unit: (Optional) Units for duration
        :param period: (Optional) How often to run the task
        :param period_unit: (Optional) Units for period
        :param utc_offset: (Optional) UTC offset for local time in the format "+1:00" or "-1:00"
        :return: uuid of created schedule
        """

        if first_time is not None:
            try:
                dt = datetime.strptime(first_time, '%m/%d/%Y %I:%M %p')

                direction = 1
                offset_h = 0
                offset_m = 0
                if utc_offset is not None:
                    if utc_offset[:1] == "-":
                        direction = -1
                    tz = datetime.strptime(utc_offset[1:], '%I:%M')
                    offset_h = direction * tz.hour
                    offset_m = direction * tz.minute

                time_json = {
                    "minute": dt.minute + offset_m,
                    "hour": dt.hour + offset_h,
                    "day_of_month": dt.day,
                    "month": dt.month,
                    "year": dt.year
                }
                print(time_json)
            except ValueError:
                return False, "BadTime"

        if ((duration is not None) ^ (duration_unit is not None)) or ((period is not None) ^ (period_unit is not None)):
            return False, "BadTime"

        if not self.valid_num(duration) or not self.valid_num(period):
            return False, "BadTime"

        if not self.valid_timetype(duration_unit) or not self.valid_timetype(period_unit):
            return False, "BadTime"

        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                r = cli.create_schedule(name, comment=comment, first_time=time_json, duration=duration,
                                        duration_unit=duration_unit, period=period, period_unit=period_unit)
                return r.data['@id']
        except exceptions.ElementExists:
            return False, "AlreadyExists"
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_create_http_alert_on_finish(self, name, url, comment=None):
        """
        Creates an HTTP GET alert that fires when a task is finished
        :param name: Name of the new alert
        :param url: URL to send an HTTP GET request to
        :param comment: (Optional) Comment to add
        :return: uuid of the created alert
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                r = cli.create_http_alert_when_finished(name, url, comment=comment)
                return r.data['@id']
        except exceptions.ElementExists:
            return False, "AlreadyExists"
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_create_task(self, name, target_uuid, config_uuid='daba56c8-73ec-11df-a475-002264764cea', scanner_uuid=None,
                        comment=None, schedule_uuid=None, alert_uuid=None):
        """
        Creates a new task
        :param name: Name of the task
        :param config_uuid: uuid of the config to use
        :param target_uuid: uuid of the target to scan
        :param scanner_uuid: (Optional) uuid of the scanner to use
        :param comment: (Optional) Comment to add
        :param schedule_uuid: (Optional) uuid of the schedule to use
        :return: uuid of the created task
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                r = cli.create_task(name, config_uuid, target_uuid, scanner_uuid=scanner_uuid, comment=comment,
                                    schedule_uuid=schedule_uuid, alert_uuid=alert_uuid)
                return r.data['@id']
        except exceptions.ElementNotFound:
            return False, "InvalidUUID"
        except exceptions.ElementExists:
            return False, "AlreadyExists"
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_start_task(self, uuid):
        """
        Starts the specified task
        :param uuid: uuid of task to execute
        :return: report uuid for this run
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                r = cli.start_task(uuid)
                return r.data['report_id']
        except exceptions.ElementNotFound:
            return False, "InvalidUUID"
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_list_port_lists(self, name=None):
        """
        Lists all defined port lists
        :param name: (Optional) Name to search for
        :return: List of matching port lists
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                if name is not None:
                    r = cli.list_port_lists(name=name)
                else:
                    r = cli.list_port_lists()
                return r.data
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_list_targets(self, name=None):
        """
        Lists all defined targets
        :param name: (Optional) Name to search for
        :return: List of matching targets
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                if name is not None:
                    r = cli.list_targets(name=name)
                else:
                    r = cli.list_targets()
                return r.data
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_list_configs(self, name=None):
        """
        Lists all defined configs
        :param name: (Optional) Name to search for
        :return: List of matching targets
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                if name is not None:
                    r = cli.list_configs(name=name)
                else:
                    r = cli.list_configs()
                return r.data
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_list_scanners(self, name=None):
        """
        Lists all defined scanners
        :param name: (Optional) Name to search for
        :return: List of matching targets
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                if name is not None:
                    r = cli.list_scanners(name=name)
                else:
                    r = cli.list_scanners()
                return r.data
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_list_schedules(self, name=None):
        """
        Lists all defined schedules
        :param name: (Optional) Name to search for
        :return: List of matching schedules
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                if name is not None:
                    r = cli.list_schedules(name=name)
                else:
                    r = cli.list_schedules()
                return r.data
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_list_tasks(self, name=None):
        """
        Lists all defined tasks
        :param name: (Optional) Name to search for
        :return: List of matching tasks
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                if name is not None:
                    r = cli.list_tasks(name=name)
                else:
                    r = cli.list_tasks()
                return r.data
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_list_reports(self, name=None):
        """
        Lists all defined reports
        :param name: (Optional) Name to search for
        :return: List of matching reports
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                if name is not None:
                    r = cli.list_reports(name=name)
                else:
                    r = cli.list_reports()
                return r.data
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def app_download_report_as_xml(self, uuid, filename):
        """
        Gets report by uuid, then writes to filename
        :param uuid: uuid of report to get
        :param filename: filename to write to
        :return:
        """
        try:
            with Client(self.h, username=self.u, password=self.device.get_encrypted_field('password'),
                        port=self.p) as cli:
                r = cli.download_report(uuid, as_element_tree=True)
                r.getroottree().write(filename)
                return True
        except exceptions.ElementNotFound:
            return False, "InvalidUUID"
        except exceptions.AuthenticationError:
            return False, "AuthError"
        except IOError:
            return False, "ConnectError"

    @action
    def parse_xml_to_csv(self, xml_filename, csv_filename, ips_only=False, hostname=None, min_severity=None,
                         max_severity=None, threat_level=None, matchfile=None):
        goxargs = ["./apps/OpenVAS/goxparse/goxparse.py", xml_filename]

        if ips_only:
            goxargs += "-ips"
        if hostname is not None:
            goxargs += "-host " + hostname
        if min_severity is not None:
            goxargs += "-cvssmin " + min_severity
        if max_severity is not None:
            goxargs += "-cvssmax " + max_severity
        if threat_level is not None:
            goxargs += "-threatlevel " + threat_level
        if matchfile is not None:
            goxargs += "-matchfile " + matchfile

        with open(csv_filename, 'w') as f:
            subprocess.Popen(goxargs, stdout=f)
            return True, 'Success'

    # @event(pull_down)
    # def test_event_action(self, data):
    #     print("in app.py")
    #     print(data)
    #     return 'Success'
    #
    # @action
    # def dummy_action(self):
    #     logger.debug("dummy")
    #     return True

    def valid_num(self, num):
        if num is not None:
            try:
                int(num)
                return True
            except ValueError:
                return False
        else:
            return True

    def valid_timetype(self, str):
        return str is None or str.lower() in ["second", "minute", "hour", "day", "week", "month", "year", "decade"]
