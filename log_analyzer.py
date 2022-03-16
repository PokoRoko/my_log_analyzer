#!/usr/bin/env python

# -*- coding: utf-8 -*-
# log_format ui_short '$remote_addr $remote_user $http_x_real_ip [$time_local] "$request" '
# '$status $body_bytes_sent "$http_referer" '
# '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
# '$request_time';

import argparse
import configparser
import datetime
import fnmatch
import gzip
import logging
import os
import re
from collections import defaultdict
from operator import itemgetter
from statistics import mean, median
from string import Template

default_config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "ALLOW_PERC_ERRORS": 50,
    "LOGGING_FILE": None,
}


def load_config(default_config):
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="./config.cfg", type=str, help="Path to config")
    args = parser.parse_args()

    if os.path.isfile(args.config):
        config_path = args.config
    elif os.path.isfile(default_config.get("CONFIG")):
        config_path = default_config.get("CONFIG")

    else:
        raise FileExistsError(f"Cant load config file {args.config}")

    config = configparser.ConfigParser(default_config, allow_no_value=True)
    config.read(config_path)
    return config


cfg = load_config(default_config)
logging.basicConfig(
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt="%Y.%m.%d %H:%M:%S",
    filename=None,
    encoding='utf-8',
    level=logging.DEBUG
)
logger = logging.getLogger()


def check_exist_report(pat, report_dir):
    date = datetime.datetime.strptime(pat, '%Y%m%d')
    pat = date.strftime("%Y.%m.%d")
    file_path = os.path.join(report_dir, f"report-{pat}.html")
    return date, os.path.isfile(file_path)


def find_last_date_log(log_dir, report_dir):
    for path, dirlist, filelist in os.walk(log_dir):
        date_list = re.findall(r'\d+', str(filelist))
        pat = max(date_list)
        date, report_exist = check_exist_report(pat, report_dir)
        if report_exist:
            logging.warning(f"last date log ({pat}) report exists")
            raise FileExistsError
        else:
            for name in fnmatch.filter(filelist, f"nginx-access-ui.log-{pat}.*"):
                logging.info(f"last date log found: {name}")
                return date, os.path.join(path, name)


def log_open(filename):
    try:
        file = gzip.open(filename) if filename.endswith(".gz") else open(filename)
        return file
    except UnicodeDecodeError as error:
        logger.exception(f"Cant read log file: {filename}\nERROR: {error}")
        return None
    except Exception as error:
        logger.exception(f"Unknown error while reading log file: {filename}\nERROR: {error}")
        raise error.__class__


def log_lines(log_file):
    for item in log_file:
        yield item


def log_parser(lines):
    logpats = r'(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})([ ](?P<xerb>.+)[ ]) - \[(?P<dateandtime>\d{2}\/[A-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2} (\+|\-)\d{4})\] ((\"(GET|POST) )(?P<url>.+)(HTTP\/1\.\S")) (?P<statuscode>\d{3}) (?P<bytessent>\d+) (["](?P<refferer>(\-)|(.+))["]) (["](?P<useragent>.+)["]) (?P<request_time>[+-]?([0-9]*[.])?[0-9]+)'
    logpat = re.compile(logpats, re.IGNORECASE)

    for line in lines:
        data = re.search(logpat, line.decode())
        if data:
            yield (data.groupdict())
        else:
            yield None


def collect_report_data(log_parse, allow_perc_error):
    logger.info("Start collect report data...")
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

    if count_none_line > len(res) * (allow_perc_error * 0.01):
        logger.warning(f"Too many errors while reading file\nAllow percent errors: {allow_perc_error}%")
        raise ValueError

    logger.info(f"Complete collect data to report. Log processed:{len(res)}. Log unread:{count_none_line}")
    return res, count_all_time


def create_report(report_data, count_all_time):
    logger.info("Start create report...")
    for url, info in report_data.items():
        res = {
            "url": url,
            "count": info["count"],
            "count_perc": (info["count"] / len(report_data) * 100).__round__(3),
            "time_avg": mean(info["list_request_time"]).__round__(3),
            "time_max": max(info["list_request_time"]),
            "time_med": median(info["list_request_time"]).__round__(3),
            "time_perc": (sum(info["list_request_time"]) / count_all_time * 100).__round__(3),
            "time_sum": sum(info["list_request_time"]).__round__(3),
        }
        yield res
    logger.info(f"Complete create report. Log: {len(report_data)}")


def render_report(cfg, date, report):
    with open("./reports/report.html", "r") as report_template:
        template = Template(report_template.read())
        report_size = int(cfg.get("Settings", "REPORT_SIZE"))
        sorted_report = sorted(list(report), key=itemgetter('time_sum'), reverse=True)
        res = template.safe_substitute(table_json=sorted_report[0:report_size])

        pat = date.strftime("%Y.%m.%d")
        file_path = os.path.join(cfg.get("Settings", "REPORT_DIR"), f"report-{pat}.html")

        report_file = open(file_path, "w")
        report_file.write(res)
        report_file.close()
        logger.info(f"Complete render report. Log: {report_size}. Path: {file_path}")


def main(cfg):
    date, filename = find_last_date_log(cfg.get("Settings", "LOG_DIR"), cfg.get("Settings", "REPORT_DIR"))
    logfiles = log_open(filename)
    loglines = log_lines(logfiles)
    log_parse = log_parser(loglines)
    report_data, count_all_time = collect_report_data(log_parse, cfg.get("Settings", "ALLOW_PERC_ERRORS"))
    report = create_report(report_data, count_all_time)
    render_report(cfg, date, report)


if __name__ == "__main__":
    main(cfg)
