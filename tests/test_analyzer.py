import datetime
import logging
import os
import sys
import unittest
from log_analyzer import *





class TestMyLogAnalyzer(unittest.TestCase):
    nginx_log = [
        b'1.99.174.176 3b81f63526fa8  - [29/Jun/2017:05:40:45 +0300] "GET /api/1/photogenic_banners/list/?server_name=WIN7RB1 HTTP/1.1" 200 12 "-" "Python-urllib/2.7" "-" "1498704044-32900793-4708-9803879" "-" 0.127\n',
        b'1.169.137.128 -  - [29/Jun/2017:05:40:45 +0300] "GET /api/v2/banner/7763463 HTTP/1.1" 200 1018 "-" "Configovod" "-" "1498704044-2118016444-4708-9803878" "712e90144abee9" 0.151\n',
    ]
    parse_log = [{'bytessent': '12',
                  'dateandtime': '29/Jun/2017:05:40:45 +0300',
                  'ipaddress': '1.99.174.176',
                  'refferer': '-',
                  'request_time': '0.127',
                  'statuscode': '200',
                  'url': '/api/1/photogenic_banners/list/?server_name=WIN7RB1 ',
                  'useragent': 'Python-urllib/2.7" "-" "1498704044-32900793-4708-9803879" "-',
                  'xerb': '3b81f63526fa8'},
                 {'bytessent': '1018',
                  'dateandtime': '29/Jun/2017:05:40:45 +0300',
                  'ipaddress': '1.169.137.128',
                  'refferer': '-',
                  'request_time': '0.151',
                  'statuscode': '200',
                  'url': '/api/v2/banner/7763463 ',
                  'useragent': 'Configovod" "-" "1498704044-2118016444-4708-9803878" '
                               '"712e90144abee9',
                  'xerb': '-'}]
    col_data = {'/api/1/photogenic_banners/list/?server_name=WIN7RB1 ': {'count': 1, 'list_request_time': [0.127]},
                '/api/v2/banner/7763463 ': {'count': 1, 'list_request_time': [0.151]}}
    all_time = 0.278
    report_data = [{'count': 1,
                    'count_perc': 50.0,
                    'time_avg': 0.127,
                    'time_max': 0.127,
                    'time_med': 0.127,
                    'time_perc': 45.683,
                    'time_sum': 0.127,
                    'url': '/api/1/photogenic_banners/list/?server_name=WIN7RB1 '},
                   {'count': 1,
                    'count_perc': 50.0,
                    'time_avg': 0.151,
                    'time_max': 0.151,
                    'time_med': 0.151,
                    'time_perc': 54.317,
                    'time_sum': 0.151,
                    'url': '/api/v2/banner/7763463 '}]

    default_config = {
        "REPORT_SIZE": 1000,
        "REPORT_DIR": "./reports",
        "LOG_DIR": "./log",
        "ALLOW_PERC_ERRORS": 50,
        "LOGGING_FILE": None,
    }
    name_log_file = "nginx-access-ui.log-20170629.gz"
    name_report_file = "report-2017.06.29.html"

    def test_check_exist_report(self):
        res = check_exist_report("19700101", "./reports")
        self.assertEqual(datetime.datetime(1970, 1, 1, 0, 0), res)

    def test_find_last_date_log(self):
        log_file = open(self.name_log_file, "w")
        report_file = open(self.name_report_file, "w")

        log_file.close()
        report_file.close()
        os.remove("./" + self.name_log_file)
        os.remove("./" + self.name_report_file)

    def test_log_open(self):
        log_file = open(self.name_log_file, "r")
        file = log_open(self.name_log_file)
        self.assertEqual(len(list(log_file)), len(list(file)))
        with self.assertRaises(FileNotFoundError):
            file = log_open("Bad_name").__next__()
        log_file.close()
        file.close()

    def test_log_parser(self):
        res = log_parser(self.nginx_log)
        self.assertEqual(list(res), self.parse_log)

    def test_collect_report_data(self):
        allow_perc_error = 1
        res, count_all_time = collect_report_data(self.parse_log, allow_perc_error)
        self.assertEqual(res.items(), self.col_data.items())
        self.assertEqual(count_all_time, self.all_time)

    def test_create_report(self):
        report = create_report(self.col_data, self.all_time)
        self.assertEqual(list(report), self.report_data)


if __name__ == '__main__':
    logger = logging.getLogger()
    from log_analyzer import check_exist_report, collect_report_data, log_parser, log_open, \
        create_report
    unittest.main()
