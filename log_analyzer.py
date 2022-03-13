#!/usr/bin/env python
# -*- coding: utf-8 -*-
# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] "$request" '
# '$status $body_bytes_sent "$http_referer" '
# '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
# '$request_time';
import argparse
import configparser
import datetime
import os
import fnmatch
import gzip
import re
from collections import defaultdict
from statistics import mean, median

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "ALLOW_PERC_ERRORS": 50
}


def load_config(config):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="./config.cfg", type=str, help="Path to config")
    args = parser.parse_args()
    config = configparser.ConfigParser(config)
    config.read(args.config)
    return config


def check_exist_reports(pat, report_dir):
    date = datetime.datetime.strptime(pat, '%Y%m%d')
    pat = date.strftime("%Y.%m.%d")
    for path, dirlist, filelist in os.walk(report_dir):
        for name in fnmatch.filter(filelist, f"report-{pat}.html"):
            return os.path.join(path, name)
    return None


def find_last_date_log(log_dir, report_dir):
    for path, dirlist, filelist in os.walk(log_dir):
        date_list = re.findall(r'\d+', str(filelist))
        pat = max(date_list)
        report = check_exist_reports(pat, report_dir)
        if report:
            return report
        else:
            for name in fnmatch.filter(filelist, f"nginx-access-ui.log-{pat}.*"):
                return os.path.join(path, name)


def log_open(filename):
    file = gzip.open(filename) if filename.endswith(".gz") else open(filename)
    return file


def log_lines(log_file):
        for item in log_file:
            yield item


def log_parser(lines):
    logpats = r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([ ](?P<xerb>.+)[ ]) - \[(?P<dateandtime>\d{2}\/[A-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST) )(?P<url>.+)(HTTP\/1\.\S")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["]) (?P<request_time>[+-]?([0-9]*[.])?[0-9]+)'
    logpat = re.compile(logpats, re.IGNORECASE)

    for line in lines:
        data = re.search(logpat, line.decode())
        if data:
            print("GOOD",line)
            yield (data.groupdict())
        else:
            print("BAD",line)
            yield None


def collect_report_data(log_parse, allow_perc_error):
    res = defaultdict(dict)
    count_all_time = 0
    count_none_line = 0

    for log in log_parse:
        if log:
            if res.get(log["url"]):
                res[log["url"]]["count"] += 1
                res[log["url"]]["list_request_time"].append(float(log["request_time"]))
            else:
                res[log["url"]]["count"] = 1
                res[log["url"]]["list_request_time"] = [float(log["request_time"])]
            count_all_time += float(log["request_time"])
        else:
            count_none_line += 1

    if count_none_line > len(res)*(allow_perc_error * 0.01):
        print(f"Too many errors while reading the file:")

    return res, count_all_time


def create_report(report_data, count_all_time):
    len_data = len(report_data)
    for url, info in report_data.items():
        res = {
            "count": info["count"],
            "count_perc": (info["count"]/len_data * 100).__round__(3),
            "time_sum": sum(info["list_request_time"]).__round__(3),
            "time_perc": (sum(info["list_request_time"])/count_all_time * 100).__round__(3),
            "time_avg": mean(info["list_request_time"]).__round__(3),
            "time_max": max(info["list_request_time"]),
            "time_med": median(info["list_request_time"]).__round__(3)
        }
        yield res


def main():
    cfg = load_config(config)
    filename = find_last_date_log(cfg.get("Settings", "LOG_DIR"), cfg.get("Settings", "REPORT_DIR"))
    logfiles = log_open(filename)
    loglines = log_lines(logfiles)
    log_parse = log_parser(loglines)
    report_data, count_all_time = collect_report_data(log_parse, cfg.get("Settings", "ALLOW_PERC_ERRORS"))
    # report = create_report(report_data, count_all_time)


if __name__ == "__main__":
    main()
