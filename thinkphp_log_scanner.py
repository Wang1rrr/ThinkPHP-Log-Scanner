#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import re
import json
import time
import datetime
import threading
import queue
import hashlib
import logging
from urllib.parse import urljoin, urlparse
from collections import defaultdict, Counter, OrderedDict
from functools import lru_cache
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from tkinter import font as tkfont
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser
import base64
import html

# 配置日志
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 禁用SSL警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ThinkPHPScanner:
    """ThinkPHP日志扫描器原始版本"""
    
    def __init__(self):
        self.version = "1.0.0"
        self.session = self.create_session()
        self.found_logs = []
        self.scanning = False
        self.max_workers = 8
        self.timeout = 10
        self.callback = None
        self.history_days = 365
        self.date_formats_priority = []
        self.current_scan_date = None
        
        # 初始化日期格式
        self.initialize_date_formats()
        
        # 调试计数器
        self.request_count = 0
        self.success_count = 0
        self.failed_count = 0
    
    def debug_log(self, message):
        """输出调试信息"""
        if self.callback:
            self.callback({
                'type': 'debug',
                'message': message
            })
    
    def set_callback(self, callback):
        """设置进度回调函数"""
        self.callback = callback
    
    def create_session(self):
        """创建HTTP会话"""
        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # 更通用的User-Agent
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # 保存原始request方法，避免递归调用
        original_request = session.request

        def request_with_timeout(method, url, **kwargs):
            return self._request_with_timeout(original_request, method, url, **kwargs)

        session.request = request_with_timeout

        return session
    
    def _request_with_timeout(self, request_func, method, url, **kwargs):
        """包装请求以添加超时"""
        if 'timeout' not in kwargs:
            kwargs['timeout'] = self.timeout
        if 'verify' not in kwargs:
            kwargs['verify'] = False
        if 'allow_redirects' not in kwargs:
            kwargs['allow_redirects'] = True
        
        self.request_count += 1
        self.debug_log(f"请求 #{self.request_count}: {method} {url}")
        
        try:
            response = request_func(method, url, **kwargs)
            self.success_count += 1
            self.debug_log(f"请求成功 #{self.request_count}: 状态码 {response.status_code}")
            return response
        except Exception as e:
            self.failed_count += 1
            self.debug_log(f"请求失败 #{self.request_count}: {str(e)}")
            raise
    
    def set_proxy(self, proxy_str):
        """设置代理"""
        if proxy_str and proxy_str.strip():
            proxy = proxy_str.strip()
            if not proxy.startswith(('http://', 'https://', 'socks5://')):
                proxy = f'http://{proxy}'
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            self.debug_log(f"设置代理: {proxy}")
    
    def initialize_date_formats(self):
        """初始化日期格式，根据ThinkPHP常见格式设置优先级"""
        # ThinkPHP常见的日期格式（按优先级排序）
        self.date_formats_priority = [
            # 1. 两位年份，下划线分隔 (25_12_01.log) - 最高优先级
            ("%y_%m_%d.log", "YY_MM_DD"),
            
            # 2. 两位年份，无分隔 (251201.log)
            ("%y%m%d.log", "YYMMDD"),
            
            # 3. 四位年份，下划线分隔 (2025_12_01.log)
            ("%Y_%m_%d.log", "YYYY_MM_DD"),
            
            # 4. 四位年份，无分隔 (20251201.log)
            ("%Y%m%d.log", "YYYYMMDD"),
            
            # 5. 两位年份，横线分隔 (25-12-01.log)
            ("%y-%m-%d.log", "YY-MM-DD"),
            
            # 6. 四位年份，横线分隔 (2025-12-01.log)
            ("%Y-%m-%d.log", "YYYY-MM-DD"),
            
            # 7. 带前缀的格式
            ("app_%y%m%d.log", "app_YYMMDD"),
            ("runtime_%y%m%d.log", "runtime_YYMMDD"),
            ("log_%y%m%d.log", "log_YYMMDD"),
            ("thinkphp_%y%m%d.log", "thinkphp_YYMMDD"),
            ("tp_%y%m%d.log", "tp_YYMMDD"),
            
            # 8. 其他可能格式
            ("%d_%m_%y.log", "DD_MM_YY"),
            ("%m_%d_%y.log", "MM_DD_YY"),
            ("%d%m%y.log", "DDMMYY"),
            ("%m%d%y.log", "MMDDYY"),
            
            # 9. ThinkPHP特定格式
            ("%Y-%m-%d_%H.log", "YYYY-MM-DD_HH"),
            ("%y%m%d_%H.log", "YYMMDD_HH"),
            ("%Y%m%d%H.log", "YYYYMMDDHH"),
            
            # 10. 更多变种
            ("%Y_%m_%d_%H%M%S.log", "YYYY_MM_DD_HHMMSS"),
            ("%y%m%d%H%M%S.log", "YYMMDDHHMMSS"),
        ]
        
        # 添加模块化的日期格式
        modules = ['Home', 'Admin', 'Api', 'Common', 'Index', 'User', 'Mobile', 'Web']
        for module in modules:
            self.date_formats_priority.extend([
                (f"%y_%m_%d_{module}.log", f"YY_MM_DD_{module}"),
                (f"{module}_%y_%m_%d.log", f"{module}_YY_MM_DD"),
                (f"%Y%m%d_{module}.log", f"YYYYMMDD_{module}"),
            ])
    
    def find_log_directory(self, base_url):
        """
        智能查找日志目录
        修复：返回所有找到的目录列表
        """
        if self.callback:
            self.callback({
                'type': 'progress',
                'message': '正在查找日志目录...',
                'value': 10
            })
        
        # ThinkPHP日志目录列表 - 添加更多子目录路径
        log_directories = [
            # ThinkPHP 3.x - 父目录
            "/Runtime/Logs/",
            "/App/Runtime/Logs/",
            "/Application/Runtime/Logs/",
            
            # ThinkPHP 3.x - 子目录（按模块）
            "/Runtime/Logs/Home/",
            "/Runtime/Logs/Admin/",
            "/Runtime/Logs/Api/",
            "/Runtime/Logs/Common/",
            "/Runtime/Logs/Index/",
            "/Runtime/Logs/User/",
            "/Runtime/Logs/Mobile/",
            "/Runtime/Logs/Web/",
            
            "/App/Runtime/Logs/Home/",
            "/App/Runtime/Logs/Admin/",
            "/App/Runtime/Logs/Api/",
            
            "/Application/Runtime/Logs/Home/",
            "/Application/Runtime/Logs/Admin/",
            "/Application/Runtime/Logs/Api/",
            "/Application/Runtime/Logs/Common/",
            "/Application/Runtime/Logs/Index/",
            "/Application/Runtime/Logs/User/",
            "/Application/Runtime/Logs/Mobile/",
            "/Application/Runtime/Logs/Web/",
            
            # ThinkPHP 5.x/6.x - 父目录
            "/runtime/log/",
            "/app/runtime/log/",
            "/data/runtime/log/",
            "/var/runtime/log/",
            
            # ThinkPHP 5.x/6.x - 子目录
            "/runtime/log/Home/",
            "/runtime/log/Admin/",
            "/runtime/log/Api/",
            
            "/app/runtime/log/Home/",
            "/app/runtime/log/Admin/",
            "/app/runtime/log/Api/",
            
            "/data/runtime/log/Home/",
            "/data/runtime/log/Admin/",
            "/data/runtime/log/Api/",
            
            # 其他常见路径
            "/log/",
            "/logs/",
            "/storage/logs/",
            "/tmp/log/",
            "/var/log/",
            
            # 目录遍历尝试
            "../runtime/log/",
            "../../runtime/log/",
            "../../../runtime/log/",
            "./runtime/log/",
            "/./runtime/log/",
            
            # 大小写变种
            "/RUNTIME/LOGS/",
            "/Runtime/logs/",
            "/runtime/Logs/",
            
            # 新的路径
            "/application/runtime/logs/",
        ]
        
        # 检测ThinkPHP版本
        version = self.detect_thinkphp_version(base_url)
        
        if self.callback:
            self.callback({
                'type': 'info',
                'message': f'检测到版本: {version}'
            })
        
        # 根据版本调整目录优先级
        if "3." in version:
            # ThinkPHP 3.x 优先检查Runtime/Logs及其子目录
            prioritized_dirs = [d for d in log_directories if "Runtime/Logs" in d or "runtime/logs" in d.lower()]
        elif "5." in version or "6." in version:
            # ThinkPHP 5.x/6.x 优先检查runtime/log及其子目录
            prioritized_dirs = [d for d in log_directories if "runtime/log" in d.lower()]
        else:
            prioritized_dirs = log_directories
        
        # 合并并去重，保持优先级
        all_dirs = []
        seen = set()
        
        # 首先添加优先级高的目录
        for d in prioritized_dirs:
            if d not in seen:
                all_dirs.append(d)
                seen.add(d)
        
        # 然后添加其他目录
        for d in log_directories:
            if d not in seen:
                all_dirs.append(d)
                seen.add(d)
        
        self.debug_log(f"将尝试 {len(all_dirs)} 个目录路径")
        
        # 并行检查目录，收集所有存在的目录
        found_dirs = []
        with ThreadPoolExecutor(max_workers=min(10, len(all_dirs))) as executor:
            future_to_dir = {}
            for i, directory in enumerate(all_dirs):
                if self.callback:
                    self.callback({
                        'type': 'detail',
                        'message': f'尝试目录: {directory}',
                        'value': 10 + (i * 30 // len(all_dirs))
                    })
                
                future = executor.submit(self.check_directory, base_url, directory)
                future_to_dir[future] = directory
            
            for future in as_completed(future_to_dir):
                directory = future_to_dir[future]
                try:
                    exists = future.result(timeout=5)
                    if exists:
                        found_dirs.append(directory)
                        if self.callback:
                            self.callback({
                                'type': 'success',
                                'message': f'找到日志目录: {directory}'
                            })
                        self.debug_log(f"找到目录: {directory}")
                except Exception as e:
                    self.debug_log(f"检查目录 {directory} 时出错: {str(e)}")
                    continue
        
        # 返回找到的所有目录
        if found_dirs:
            if self.callback:
                self.callback({
                    'type': 'info',
                    'message': f'总共找到 {len(found_dirs)} 个日志目录'
                })
            
            # 排序：优先子目录，后父目录
            found_dirs.sort(key=lambda x: (x.count('/'), x))
            return found_dirs
        else:
            return None
    
    def check_directory(self, base_url, directory):
        """检查目录是否存在"""
        try:
            test_url = urljoin(base_url, directory)
            self.debug_log(f"检查目录: {test_url}")
            
            # 尝试GET请求，因为HEAD可能被屏蔽
            response = self.session.get(test_url, timeout=3, verify=False, allow_redirects=True)
            
            self.debug_log(f"目录检查结果 - URL: {test_url}, 状态码: {response.status_code}")
            
            # 放宽条件，只要不是404就认为可能存在
            if response.status_code == 200:
                content = response.text.lower()
                if any(keyword in content for keyword in ['index of', 'directory', '<directory', 'parent directory', '.log', 'logs', 'thinkphp']):
                    self.debug_log(f"目录存在且包含日志关键词: {test_url}")
                    return True
                else:
                    self.debug_log(f"目录存在但未找到关键词: {test_url}")
                    # 即使没有关键词，也返回True，因为可能是其他页面但目录存在
                    return True
            elif response.status_code == 403:
                self.debug_log(f"目录访问被拒绝(403): {test_url}")
                return True  # 403表示目录存在但无权限
            elif response.status_code in [301, 302]:
                self.debug_log(f"目录重定向: {test_url} -> {response.headers.get('Location')}")
                return True
            elif response.status_code != 404:
                self.debug_log(f"目录返回非404状态码: {test_url} - {response.status_code}")
                return True  # 其他状态码也认为目录可能存在
            
        except requests.exceptions.Timeout:
            self.debug_log(f"目录检查超时: {test_url}")
        except requests.exceptions.ConnectionError:
            self.debug_log(f"目录连接错误: {test_url}")
        except Exception as e:
            self.debug_log(f"目录检查异常: {test_url} - {str(e)}")
        
        return False
    
    def detect_thinkphp_version(self, url):
        """检测ThinkPHP版本"""
        try:
            response = self.session.get(url, timeout=5, verify=False)
            content = response.text
            
            # 检查ThinkPHP标识
            thinkphp_patterns = [
                r'ThinkPHP[^\d]*([3-6]\.[0-9x\.]+)',
                r'thinkphp[^\d]*([3-6]\.[0-9x\.]+)',
                r'/ThinkPHP/([3-6]\.[0-9x\.]+)/',
                r'/thinkphp/([3-6]\.[0-9x\.]+)/',
                r'ThinkPHP V([3-6]\.[0-9x\.]+)',
                r'thinkphp v([3-6]\.[0-9x\.]+)',
            ]
            
            for pattern in thinkphp_patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1)
                    self.debug_log(f"从页面内容检测到ThinkPHP版本: {version}")
                    return f"ThinkPHP {version}"
            
            # 检查特定路径
            test_paths = [
                ('/?s=index/index/test', 'ThinkPHP 5.x'),
                ('/?s=/Index/index', 'ThinkPHP 3.x'),
                ('/index.php?s=index/index/test', 'ThinkPHP 5.x'),
                ('/index.php?s=/Index/index', 'ThinkPHP 3.x'),
                ('/index.php', '未知版本'),
            ]
            
            for path, version in test_paths:
                try:
                    test_url = urljoin(url, path)
                    resp = self.session.get(test_url, timeout=2, verify=False)
                    if resp.status_code < 500 and resp.status_code != 404:
                        self.debug_log(f"通过路径 {path} 检测到版本: {version}")
                        return version
                except Exception as e:
                    continue
            
        except Exception as e:
            self.debug_log(f"检测版本时出错: {str(e)}")
        
        return "未知版本"
    
    def scan_log_files_in_directory(self, base_url, directories):
        """
        在指定目录中扫描日志文件
        修改：支持多个目录
        """
        found_logs = []
        
        if self.callback:
            self.callback({
                'type': 'progress',
                'message': '开始扫描日志文件...',
                'value': 40
            })
        
        # 如果传入的是单个目录，转换为列表
        if isinstance(directories, str):
            directories = [directories]
        
        self.debug_log(f"开始扫描 {len(directories)} 个目录")
        
        # 遍历所有目录
        for dir_index, directory in enumerate(directories):
            self.debug_log(f"扫描目录 {dir_index+1}/{len(directories)}: {directory}")
            
            if self.callback:
                self.callback({
                    'type': 'info',
                    'message': f'扫描目录: {directory}'
                })
            
            # 1. 首先尝试固定名称的日志文件
            fixed_logs = self.try_fixed_log_files(base_url, directory)
            found_logs.extend(fixed_logs)
            
            if fixed_logs and self.callback:
                self.callback({
                    'type': 'success',
                    'message': f'在 {directory} 找到 {len(fixed_logs)} 个固定名称日志文件'
                })
            
            # 2. 如果没有找到固定日志，尝试日期格式的日志
            if not found_logs:
                if self.callback:
                    self.callback({
                        'type': 'info',
                        'message': f'在 {directory} 未找到固定名称日志，开始扫描日期格式日志...'
                    })
                
                self.debug_log(f"在 {directory} 未找到固定日志，开始扫描日期格式日志")
                
                # 首先生成今天和昨天的日志文件名进行快速测试
                today = datetime.datetime.now()
                yesterday = today - datetime.timedelta(days=1)
                
                quick_test_filenames = []
                for date in [today, yesterday]:
                    # 生成所有可能的日期格式
                    for fmt, _ in self.date_formats_priority[:8]:  # 只尝试前8种格式
                        filename = date.strftime(fmt)
                        quick_test_filenames.append(filename)
                
                # 去重
                quick_test_filenames = list(set(quick_test_filenames))
                
                if self.callback:
                    self.callback({
                        'type': 'detail',
                        'message': f'在 {directory} 快速测试 {len(quick_test_filenames)} 个日期格式文件...'
                    })
                
                self.debug_log(f"快速测试文件名: {quick_test_filenames}")
                
                # 尝试快速测试
                test_log = self.try_single_log_file(base_url, directory, quick_test_filenames)
                if test_log:
                    found_logs.append(test_log)
                    
                    if self.callback:
                        self.callback({
                            'type': 'found',
                            'message': f'✓ 在 {directory} 找到日期日志: {test_log.get("filename")}',
                            'log': test_log
                        })
                    
                    self.debug_log(f"快速测试找到日志: {test_log.get('filename')}")
                    
                    # 如果找到了一个日志，开始扩展扫描
                    date_logs = self.expand_date_scan(base_url, directory, test_log)
                    found_logs.extend(date_logs)
                    
                    if date_logs and self.callback:
                        self.callback({
                            'type': 'success',
                            'message': f'在 {directory} 扩展扫描找到 {len(date_logs)} 个日期日志'
                        })
            else:
                # 3. 如果已经找到固定日志，也尝试日期日志
                if self.callback:
                    self.callback({
                        'type': 'info',
                        'message': f'在 {directory} 继续扫描日期格式日志...'
                    })
                
                self.debug_log(f"在 {directory} 已找到固定日志，继续扫描日期日志")
                
                date_logs = self.expand_date_scan(base_url, directory, None)
                found_logs.extend(date_logs)
                
                if date_logs and self.callback:
                    self.callback({
                        'type': 'success',
                        'message': f'在 {directory} 额外找到 {len(date_logs)} 个日期日志'
                    })
            
            # 更新进度
            if self.callback:
                self.callback({
                    'type': 'progress',
                    'value': 40 + ((dir_index + 1) * 50 // len(directories))
                })
        
        self.debug_log(f"所有目录扫描完成，总共找到 {len(found_logs)} 个日志文件")
        
        # 去重：根据URL去重，避免同一个文件在不同目录中被重复发现
        unique_logs = []
        seen_urls = set()
        for log in found_logs:
            url = log.get('url')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_logs.append(log)
        
        self.debug_log(f"去重后剩余 {len(unique_logs)} 个唯一日志文件")
        return unique_logs
    
    def try_fixed_log_files(self, base_url, directory):
        """尝试固定名称的日志文件"""
        fixed_names = [
            "app.log", "runtime.log", "error.log", "debug.log",
            "sql.log", "test.log", "access.log", "system.log",
            "default.log", "main.log", "web.log", "admin.log",
            "api.log", "mobile.log", "user.log", "security.log",
            "thinkphp.log", "tp.log", "log.log", "logs.log",
            "today.log", "yesterday.log", "current.log",
            # 新增常见日志文件名
            "think.log", "framework.log", "laravel.log", 
            "error_log", "php_error_log", "cgi_error_log",
            "application.log", "production.log", "development.log",
            "info.log", "warning.log", "critical.log",
            "Home", "Admin", "Api",  # 可能是目录也可能是文件
        ]
        
        found_logs = []
        
        if self.callback:
            self.callback({
                'type': 'detail',
                'message': f'正在扫描 {len(fixed_names)} 个固定名称日志...'
            })
        
        self.debug_log(f"开始扫描固定名称日志，目录: {directory}")
        
        with ThreadPoolExecutor(max_workers=min(10, len(fixed_names))) as executor:
            future_to_name = {}
            for filename in fixed_names:
                log_url = urljoin(base_url, f"{directory.rstrip('/')}/{filename}")
                future = executor.submit(self.try_download_single_log, log_url)
                future_to_name[future] = filename
            
            for i, future in enumerate(as_completed(future_to_name)):
                filename = future_to_name[future]
                try:
                    result = future.result(timeout=5)
                    if result and result.get('status') == 'success':
                        found_logs.append(result)
                        if self.callback:
                            self.callback({
                                'type': 'found',
                                'message': f'✓ 找到日志: {filename}',
                                'log': result
                            })
                        self.debug_log(f"找到固定日志: {filename}")
                    elif result:
                        status_code = result.get('status_code', 'N/A')
                        error = result.get('error', '未知错误')
                        if status_code not in [404]:
                            self.debug_log(f"固定日志 {filename} 返回状态码 {status_code}: {error}")
                except Exception as e:
                    if self.callback:
                        self.callback({
                            'type': 'error',
                            'message': f'! 扫描出错: {filename} ({str(e)})'
                        })
                    self.debug_log(f"扫描固定日志 {filename} 时出错: {str(e)}")
                
                # 更新进度
                if self.callback:
                    self.callback({
                        'type': 'progress',
                        'value': 45 + (i * 15 // len(fixed_names))
                    })
        
        self.debug_log(f"固定名称扫描完成，找到 {len(found_logs)} 个日志")
        return found_logs
    
    def try_single_log_file(self, base_url, directory, filenames):
        """尝试单个日志文件"""
        for filename in filenames:
            log_url = urljoin(base_url, f"{directory.rstrip('/')}/{filename}")
            self.debug_log(f"尝试日志文件: {log_url}")
            result = self.try_download_single_log(log_url)
            if result and result.get('status') == 'success':
                self.debug_log(f"成功找到日志: {filename}")
                return result
            elif result:
                status_code = result.get('status_code', 'N/A')
                if status_code != 404:
                    self.debug_log(f"日志 {filename} 返回状态码 {status_code}: {result.get('error', '')}")
        return None
    
    def expand_date_scan(self, base_url, directory, first_log=None):
        """
        扩展日期扫描
        基于找到的第一个日志，向前和向后扩展
        """
        found_logs = []
        
        # 确定起始日期
        if first_log:
            # 从日志文件名中提取日期
            date_str = self.extract_date_from_filename(first_log.get('filename', ''))
            if date_str:
                try:
                    start_date = datetime.datetime.strptime(date_str, "%Y_%m_%d")
                except:
                    start_date = datetime.datetime.now()
            else:
                start_date = datetime.datetime.now()
        else:
            start_date = datetime.datetime.now()
        
        if self.callback:
            self.callback({
                'type': 'info',
                'message': f'从日期 {start_date.strftime("%Y-%m-%d")} 开始扩展扫描'
            })
        
        self.debug_log(f"扩展扫描起始日期: {start_date.strftime('%Y-%m-%d')}")
        
        # 向前扫描（过去的日期）
        past_logs = self.scan_past_dates(base_url, directory, start_date)
        found_logs.extend(past_logs)
        
        # 向后扫描（未来的日期）
        future_logs = self.scan_future_dates(base_url, directory, start_date)
        found_logs.extend(future_logs)
        
        self.debug_log(f"扩展扫描完成，找到 {len(found_logs)} 个日志")
        return found_logs
    
    def scan_past_dates(self, base_url, directory, start_date):
        """扫描过去的日期 - 详细输出"""
        found_logs = []
        empty_days = 0
        max_empty_days = 30  # 连续30天没有日志就停止
        
        current_date = start_date
        total_scanned = 0
        
        self.debug_log(f"开始扫描过去日期，从 {start_date.strftime('%Y-%m-%d')} 开始")
        
        while empty_days < max_empty_days:
            self.current_scan_date = current_date
            
            # 输出当前扫描的日期
            if self.callback:
                self.callback({
                    'type': 'date_scan',
                    'message': f'扫描日期: {current_date.strftime("%Y-%m-%d")}',
                    'date': current_date
                })
            
            # 生成当前日期的所有可能文件名
            date_filenames = self.generate_filenames_for_date(current_date)
            total_scanned += len(date_filenames)
            
            if self.callback:
                self.callback({
                    'type': 'detail',
                    'message': f'为日期 {current_date.strftime("%Y-%m-%d")} 生成 {len(date_filenames)} 个文件名'
                })
            
            # 检查是否有日志文件
            has_log = False
            for filename in date_filenames:
                log_url = urljoin(base_url, f"{directory.rstrip('/')}/{filename}")
                
                # 输出尝试的文件名
                if self.callback:
                    self.callback({
                        'type': 'detail',
                        'message': f'  尝试: {filename}'
                    })
                
                result = self.try_download_single_log(log_url)
                if result and result.get('status') == 'success':
                    found_logs.append(result)
                    has_log = True
                    
                    if self.callback:
                        self.callback({
                            'type': 'found',
                            'message': f'  ✓ 找到历史日志: {filename}',
                            'log': result
                        })
                    self.debug_log(f"找到历史日志: {filename}")
                elif result and result.get('status') == 'error':
                    # 只输出特定的错误类型
                    error = result.get('error', '')
                    status_code = result.get('status_code', '')
                    if status_code not in [404, 403]:
                        if self.callback:
                            self.callback({
                                'type': 'error',
                                'message': f'  ✗ {filename}: {error}'
                            })
                        self.debug_log(f"日志 {filename} 返回错误: {error}")
            
            if has_log:
                empty_days = 0  # 重置空天数计数器
            else:
                empty_days += 1
                if self.callback:
                    self.callback({
                        'type': 'info',
                        'message': f'日期 {current_date.strftime("%Y-%m-%d")} 未找到日志 (连续 {empty_days} 天)'
                    })
            
            # 前一天
            current_date -= datetime.timedelta(days=1)
            
            # 更新进度
            if self.callback:
                self.callback({
                    'type': 'progress',
                    'value': 60 + (total_scanned * 20 // (max_empty_days * len(date_filenames)))
                })
            
            # 安全限制，最多扫描500天
            if (start_date - current_date).days > 500:
                self.debug_log("达到最大扫描天数限制（500天）")
                break
        
        self.debug_log(f"过去日期扫描完成，找到 {len(found_logs)} 个日志")
        return found_logs
    
    def scan_future_dates(self, base_url, directory, start_date):
        """扫描未来的日期 - 详细输出"""
        found_logs = []
        max_empty_days = 7  # 未来只扫描7天
        
        current_date = start_date + datetime.timedelta(days=1)
        days_scanned = 0
        
        self.debug_log(f"开始扫描未来日期，从 {current_date.strftime('%Y-%m-%d')} 开始")
        
        while days_scanned < max_empty_days:
            self.current_scan_date = current_date
            
            # 输出当前扫描的日期
            if self.callback:
                self.callback({
                    'type': 'date_scan',
                    'message': f'扫描未来日期: {current_date.strftime("%Y-%m-%d")}',
                    'date': current_date
                })
            
            # 生成当前日期的所有可能文件名
            date_filenames = self.generate_filenames_for_date(current_date)
            
            if self.callback:
                self.callback({
                    'type': 'detail',
                    'message': f'为未来日期 {current_date.strftime("%Y-%m-%d")} 生成 {len(date_filenames)} 个文件名'
                })
            
            # 检查是否有日志文件
            for filename in date_filenames:
                log_url = urljoin(base_url, f"{directory.rstrip('/')}/{filename}")
                
                # 输出尝试的文件名
                if self.callback:
                    self.callback({
                        'type': 'detail',
                        'message': f'  尝试: {filename}'
                    })
                
                result = self.try_download_single_log(log_url)
                if result and result.get('status') == 'success':
                    found_logs.append(result)
                    
                    if self.callback:
                        self.callback({
                            'type': 'found',
                            'message': f'  ✓ 找到未来日志: {filename}',
                            'log': result
                        })
                    self.debug_log(f"找到未来日志: {filename}")
                elif result and result.get('status') == 'error':
                    error = result.get('error', '')
                    status_code = result.get('status_code', '')
                    if status_code not in [404, 403]:
                        if self.callback:
                            self.callback({
                                'type': 'error',
                                'message': f'  ✗ {filename}: {error}'
                            })
                        self.debug_log(f"未来日志 {filename} 返回错误: {error}")
            
            current_date += datetime.timedelta(days=1)
            days_scanned += 1
            
            # 更新进度
            if self.callback:
                self.callback({
                    'type': 'progress',
                    'value': 80 + (days_scanned * 10 // max_empty_days)
                })
        
        self.debug_log(f"未来日期扫描完成，找到 {len(found_logs)} 个日志")
        return found_logs
    
    def deep_date_scan(self, base_url, directory):
        """深度日期扫描 - 详细输出"""
        found_logs = []
        
        # 确定扫描日期范围（最近history_days天）
        end_date = datetime.datetime.now()
        start_date = end_date - datetime.timedelta(days=self.history_days)
        
        if self.callback:
            self.callback({
                'type': 'info',
                'message': f'深度扫描 {self.history_days} 天内的日期日志 ({start_date.strftime("%Y-%m-%d")} 到 {end_date.strftime("%Y-%m-%d")})'
            })
        
        self.debug_log(f"深度日期扫描范围: {start_date.strftime('%Y-%m-%d')} 到 {end_date.strftime('%Y-%m-%d')}")
        
        # 将日期范围分成多个区间
        date_ranges = self.split_date_range(start_date, end_date, chunks=10)
        
        total_found = 0
        for range_idx, (range_start, range_end) in enumerate(date_ranges):
            if self.callback:
                self.callback({
                    'type': 'info',
                    'message': f'扫描区间 {range_idx+1}/{len(date_ranges)}: {range_start.strftime("%Y-%m-%d")} 到 {range_end.strftime("%Y-%m-%d")}'
                })
            
            range_logs = self.scan_date_range(base_url, directory, range_start, range_end)
            found_logs.extend(range_logs)
            total_found += len(range_logs)
            
            if self.callback:
                self.callback({
                    'type': 'detail',
                    'message': f'区间 {range_idx+1} 扫描完成，找到 {len(range_logs)} 个日志 (总计: {total_found})'
                })
            
            self.debug_log(f"区间 {range_idx+1} 扫描完成，找到 {len(range_logs)} 个日志")
        
        self.debug_log(f"深度日期扫描完成，总共找到 {total_found} 个日志")
        return found_logs
    
    def split_date_range(self, start_date, end_date, chunks=10):
        """将日期范围分割成多个区间"""
        date_ranges = []
        total_days = (end_date - start_date).days
        
        if total_days <= 0:
            return [(start_date, end_date)]
        
        chunk_days = max(1, total_days // chunks)
        
        current_start = start_date
        while current_start < end_date:
            current_end = current_start + datetime.timedelta(days=chunk_days)
            if current_end > end_date:
                current_end = end_date
            
            date_ranges.append((current_start, current_end))
            current_start = current_end + datetime.timedelta(days=1)
        
        return date_ranges
    
    def scan_date_range(self, base_url, directory, start_date, end_date):
        """扫描指定日期范围内的日志"""
        found_logs = []
        current_date = start_date
        total_days = (end_date - start_date).days + 1
        scanned_days = 0
        
        # 优先尝试的日期格式
        priority_formats = [
            "%y_%m_%d.log",    # 25_12_01.log
            "%y%m%d.log",      # 251201.log
            "%Y_%m_%d.log",    # 2025_12_01.log
            "%Y%m%d.log",      # 20251201.log
            "%y-%m-%d.log",    # 25-12-01.log
            "%Y-%m-%d.log",    # 2025-12-01.log
            "app_%y%m%d.log",  # app_251201.log
            "runtime_%y%m%d.log",  # runtime_251201.log
        ]
        
        self.debug_log(f"开始扫描日期范围: {start_date.strftime('%Y-%m-%d')} 到 {end_date.strftime('%Y-%m-%d')}")
        
        while current_date <= end_date:
            self.current_scan_date = current_date
            scanned_days += 1
            
            # 每10天输出一次进度
            if scanned_days % 10 == 0 and self.callback:
                self.callback({
                    'type': 'progress_detail',
                    'message': f'深度扫描进度: {scanned_days}/{total_days} 天 ({current_date.strftime("%Y-%m-%d")})',
                    'value': scanned_days,
                    'total': total_days
                })
            
            # 为当前日期生成所有优先级格式的文件名
            date_filenames = []
            for fmt in priority_formats:
                filename = current_date.strftime(fmt)
                date_filenames.append(filename)
            
            # 尝试下载这些文件
            for filename in date_filenames:
                log_url = urljoin(base_url, f"{directory.rstrip('/')}/{filename}")
                
                # 输出尝试的文件名
                if scanned_days % 5 == 0 and self.callback:  # 每5天输出一次详细尝试
                    self.callback({
                        'type': 'detail',
                        'message': f'  深度扫描尝试: {filename}'
                    })
                
                result = self.try_download_single_log(log_url)
                if result and result.get('status') == 'success':
                    found_logs.append(result)
                    
                    if self.callback:
                        self.callback({
                            'type': 'found',
                            'message': f'  ✓ 深度扫描找到: {filename}',
                            'log': result
                        })
                    self.debug_log(f"深度扫描找到日志: {filename}")
                    break  # 找到一个就跳出，避免重复
            
            current_date += datetime.timedelta(days=1)
        
        self.debug_log(f"日期范围扫描完成，找到 {len(found_logs)} 个日志")
        return found_logs
    
    @lru_cache(maxsize=2048)
    def _cached_filenames_for_date(self, date_key):
        """缓存日期对应的文件名集合"""
        date = datetime.datetime.strptime(date_key, "%Y-%m-%d")
        filenames = []
        for fmt, _ in self.date_formats_priority:
            try:
                filenames.append(date.strftime(fmt))
            except Exception:
                continue
        # 使用dict保持首次出现顺序
        return tuple(dict.fromkeys(filenames))
    
    def generate_filenames_for_date(self, date):
        """为指定日期生成所有可能的文件名（带缓存）"""
        date_key = date.strftime("%Y-%m-%d")
        return list(self._cached_filenames_for_date(date_key))
    
    def extract_date_from_filename(self, filename):
        """从文件名中提取日期"""
        if not filename:
            return None
        
        # 尝试多种日期格式
        date_patterns = [
            # 25_12_01
            (r'(\d{2})_(\d{2})_(\d{2})', lambda m: datetime.datetime(
                int(f"20{m.group(1)}") if int(m.group(1)) < 50 else int(f"19{m.group(1)}"),
                int(m.group(2)), 
                int(m.group(3))
            )),
            # 2025_12_01
            (r'(\d{4})_(\d{2})_(\d{2})', lambda m: datetime.datetime(
                int(m.group(1)), 
                int(m.group(2)), 
                int(m.group(3))
            )),
            # 251201
            (r'(\d{2})(\d{2})(\d{2})', lambda m: datetime.datetime(
                int(f"20{m.group(1)}") if int(m.group(1)) < 50 else int(f"19{m.group(1)}"),
                int(m.group(2)), 
                int(m.group(3))
            )),
            # 20251201
            (r'(\d{4})(\d{2})(\d{2})', lambda m: datetime.datetime(
                int(m.group(1)), 
                int(m.group(2)), 
                int(m.group(3))
            )),
            # 25-12-01
            (r'(\d{2})-(\d{2})-(\d{2})', lambda m: datetime.datetime(
                int(f"20{m.group(1)}") if int(m.group(1)) < 50 else int(f"19{m.group(1)}"),
                int(m.group(2)), 
                int(m.group(3))
            )),
            # 2025-12-01
            (r'(\d{4})-(\d{2})-(\d{2})', lambda m: datetime.datetime(
                int(m.group(1)), 
                int(m.group(2)), 
                int(m.group(3))
            )),
        ]
        
        for pattern, converter in date_patterns:
            match = re.search(pattern, filename)
            if match:
                try:
                    return converter(match).strftime("%Y_%m_%d")
                except:
                    continue
        
        return None
    
    def try_download_single_log(self, log_url):
        """尝试下载单个日志文件"""
        try:
            self.debug_log(f"下载日志: {log_url}")
            response = self.session.get(log_url, timeout=self.timeout, verify=False, stream=True)
            
            self.debug_log(f"日志响应状态码: {response.status_code}")
            
            if response.status_code == 200:
                # 读取内容
                content = response.text
                
                # 检查是否是有效的日志文件
                is_log, reason = self.is_likely_log_file(content)
                if is_log:
                    log_data = {
                        'url': log_url,
                        'filename': log_url.split('/')[-1],
                        'content': content,
                        'size': len(content),
                        'status': 'success',
                        'status_code': response.status_code,
                        'lines': len(content.split('\n')),
                        'content_preview': content[:500] + '...' if len(content) > 500 else content,
                        'line_positions': self.extract_line_positions(content)
                    }
                    self.debug_log(f"日志文件有效: {log_url} (大小: {len(content)} 字节)")
                    return log_data
                else:
                    self.debug_log(f"不是有效的日志文件: {log_url} - 原因: {reason}")
                    return {
                        'url': log_url,
                        'filename': log_url.split('/')[-1],
                        'status': 'error',
                        'error': f'不是有效的日志文件: {reason}',
                        'status_code': response.status_code
                    }
            elif response.status_code == 404:
                self.debug_log(f"日志文件不存在 (404): {log_url}")
                return {
                    'url': log_url,
                    'filename': log_url.split('/')[-1],
                    'status': 'error',
                    'error': 'HTTP 404 - 文件不存在',
                    'status_code': 404
                }
            elif response.status_code == 403:
                self.debug_log(f"日志文件禁止访问 (403): {log_url}")
                return {
                    'url': log_url,
                    'filename': log_url.split('/')[-1],
                    'status': 'error',
                    'error': 'HTTP 403 - 禁止访问',
                    'status_code': 403
                }
            else:
                self.debug_log(f"日志文件返回状态码 {response.status_code}: {log_url}")
                return {
                    'url': log_url,
                    'filename': log_url.split('/')[-1],
                    'status': 'error',
                    'error': f'HTTP {response.status_code}',
                    'status_code': response.status_code
                }
        
        except requests.exceptions.Timeout:
            self.debug_log(f"日志请求超时: {log_url}")
            return {
                'url': log_url,
                'filename': log_url.split('/')[-1],
                'status': 'error',
                'error': '请求超时'
            }
        except requests.exceptions.ConnectionError:
            self.debug_log(f"日志连接错误: {log_url}")
            return {
                'url': log_url,
                'filename': log_url.split('/')[-1],
                'status': 'error',
                'error': '连接错误'
            }
        except Exception as e:
            self.debug_log(f"日志下载异常: {log_url} - {str(e)}")
            return {
                'url': log_url,
                'filename': log_url.split('/')[-1],
                'status': 'error',
                'error': str(e)
            }
    
    def extract_line_positions(self, content):
        """提取行号位置信息，用于快速定位"""
        lines = content.split('\n')
        line_positions = {}
        current_pos = 0
        
        for i, line in enumerate(lines, 1):
            line_positions[i] = {
                'start': current_pos,
                'end': current_pos + len(line),
                'length': len(line),
                'content_preview': line[:100] + '...' if len(line) > 100 else line
            }
            current_pos += len(line) + 1  # +1 for newline
        
        return line_positions
    
    def is_likely_log_file(self, content):
        """判断内容是否可能是日志文件"""
        if not content:
            return False, "内容为空"
        
        content = content.strip()
        if len(content) < 10:
            return False, "内容太短"
        
        # 检查常见日志特征
        log_indicators = [
            # 日期时间格式
            (r'\d{4}[-/]\d{2}[-/]\d{2}', 3),
            (r'\d{2}[-/]\d{2}[-/]\d{4}', 3),
            (r'\d{2}:\d{2}:\d{2}', 2),
            # ThinkPHP特定
            ('ThinkPHP', 5),
            ('thinkphp', 5),
            ('[ info ]', 3),
            ('[ error ]', 3),
            ('[ sql ]', 3),
            ('[ debug ]', 3),
            # PHP相关
            ('PHP', 2),
            ('php', 2),
            ('Notice:', 3),
            ('Warning:', 3),
            ('Error:', 3),
            ('Exception', 3),
            # 日志级别
            ('INFO', 2),
            ('ERROR', 2),
            ('WARNING', 2),
            ('DEBUG', 2),
            # SQL相关
            ('SQL:', 3),
            ('SELECT', 2),
            ('INSERT', 2),
            ('UPDATE', 2),
            ('DELETE', 2),
            # 其他常见日志内容
            ('stack trace', 3),
            ('traceback', 3),
            ('file:', 2),
            ('line:', 2),
            ('at ', 2),
        ]
        
        # 检查前2000个字符
        sample = content[:2000]
        
        score = 0
        reasons = []
        for indicator, points in log_indicators:
            if isinstance(indicator, str):
                if indicator.lower() in sample.lower():
                    score += points
                    reasons.append(indicator)
            else:
                if re.search(indicator, sample):
                    score += points
                    reasons.append(indicator)
        
        # 放宽条件：如果包含任何ThinkPHP关键词，直接认为是日志
        if 'ThinkPHP' in content or 'thinkphp' in content:
            self.debug_log(f"日志判定: 包含ThinkPHP关键词，分数: {score}")
            return True, "包含ThinkPHP关键词"
        
        self.debug_log(f"日志判定分数: {score}, 原因: {reasons}")
        
        # 调整阈值：从5降到3
        if score >= 3:
            return True, f"分数{score}足够高"
        else:
            return False, f"分数{score}不足"
    
    def stop_scan(self):
        """停止扫描"""
        self.scanning = False
        self.debug_log("扫描已停止")


class ScannerGUI:
    """ThinkPHP日志扫描器图形界面"""
    
    def __init__(self):
        self.scanner = ThinkPHPScanner()
        self.root = tk.Tk()
        self.root.title(f"ThinkPHP日志扫描器 v{self.scanner.version}")
        self.root.geometry("1200x800")
        
        # 设置图标和主题
        self.setup_icons()
        
        # 创建界面
        self.create_interface()
        
        # 初始化变量
        self.scanning = False
        self.found_logs = []
        self.current_analysis = None
        
        # Treeview item到log数据的映射
        self.tree_item_data = {}
        
        # 配置网格权重
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_icons(self):
        """设置图标"""
        try:
            if os.path.exists('icon.ico'):
                self.root.iconbitmap('icon.ico')
        except:
            pass
    
    def create_interface(self):
        """创建主界面"""
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="5")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置网格权重
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=3)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # 顶部工具栏
        self.create_toolbar(main_frame)
        
        # 左侧主内容区
        self.create_main_content(main_frame)
        
        # 右侧控制面板
        self.create_control_panel(main_frame)
        
        # 底部状态栏
        self.create_status_bar(main_frame)
    
    def create_toolbar(self, parent):
        """创建工具栏"""
        toolbar = ttk.Frame(parent, relief=tk.RAISED, borderwidth=1)
        toolbar.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 5))
        
        # 标题
        title_label = ttk.Label(toolbar, text="ThinkPHP日志扫描器", 
                               font=("Arial", 14, "bold"))
        title_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # 版本标签
        version_label = ttk.Label(toolbar, text=f"v{self.scanner.version}",
                                 font=("Arial", 10))
        version_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        # 分隔符
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        # 快速操作按钮
        quick_actions = ttk.Frame(toolbar)
        quick_actions.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(quick_actions, text="清空结果", command=self.clear_results,
                  width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_actions, text="导出报告", command=self.export_report,
                  width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_actions, text="导出SQL", command=self.export_sql_queries,
                  width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_actions, text="调试模式", command=self.toggle_debug,
                  width=10).pack(side=tk.LEFT, padx=2)
        ttk.Button(quick_actions, text="帮助", command=self.show_help,
                  width=10).pack(side=tk.LEFT, padx=2)
    
    def create_main_content(self, parent):
        """创建主内容区"""
        main_content = ttk.Frame(parent)
        main_content.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 5))
        main_content.grid_rowconfigure(0, weight=1)
        main_content.grid_columnconfigure(0, weight=1)
        
        # 创建标签页
        self.notebook = ttk.Notebook(main_content)
        self.notebook.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 扫描进度标签页
        self.create_scan_tab()
        
        # 日志查看标签页
        self.create_log_viewer_tab()
        
        # 调试信息标签页
        self.create_debug_tab()
        
        # 分析结果标签页
        self.create_analysis_tab()
        
        # 统计信息标签页
        self.create_stats_tab()
    
    def create_scan_tab(self):
        """创建扫描进度标签页"""
        scan_frame = ttk.Frame(self.notebook)
        self.notebook.add(scan_frame, text="扫描进度")
        
        # 配置网格
        scan_frame.grid_rowconfigure(1, weight=1)
        scan_frame.grid_columnconfigure(0, weight=1)
        
        # 实时日志显示
        log_display_frame = ttk.LabelFrame(scan_frame, text="实时扫描日志", padding="10")
        log_display_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N), pady=(0, 10))
        log_display_frame.grid_columnconfigure(0, weight=1)
        
        # 日志计数器
        counter_frame = ttk.Frame(log_display_frame)
        counter_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 5))
        
        self.found_count_label = ttk.Label(counter_frame, text="找到: 0", foreground="green")
        self.found_count_label.pack(side=tk.LEFT, padx=(0, 20))
        
        self.error_count_label = ttk.Label(counter_frame, text="错误: 0", foreground="red")
        self.error_count_label.pack(side=tk.LEFT)
        
        # 当前扫描目录显示
        self.current_dir_label = ttk.Label(counter_frame, text="当前目录: 无")
        self.current_dir_label.pack(side=tk.RIGHT)
        
        # 实时日志显示区域
        self.realtime_log_text = scrolledtext.ScrolledText(
            log_display_frame, 
            height=15,
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.realtime_log_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 配置标签
        self.realtime_log_text.tag_config("success", foreground="green", font=("Consolas", 9, "bold"))
        self.realtime_log_text.tag_config("error", foreground="red", font=("Consolas", 9, "bold"))
        self.realtime_log_text.tag_config("info", foreground="blue")
        self.realtime_log_text.tag_config("detail", foreground="#666666")
        self.realtime_log_text.tag_config("found", foreground="dark green", font=("Consolas", 9, "bold"))
        self.realtime_log_text.tag_config("date_scan", foreground="dark orange", font=("Consolas", 9, "bold"))
        self.realtime_log_text.tag_config("debug", foreground="purple")
        
        # 扫描详情
        details_frame = ttk.LabelFrame(scan_frame, text="扫描详情", padding="10")
        details_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        details_frame.grid_rowconfigure(0, weight=1)
        details_frame.grid_columnconfigure(0, weight=1)
        
        # 创建Treeview显示找到的日志
        columns = ('文件名', '大小', '行数', '状态', 'URL', '目录')
        self.logs_tree = ttk.Treeview(details_frame, columns=columns, show='headings', height=10)
        
        # 设置列
        col_widths = {'文件名': 120, '大小': 80, '行数': 60, '状态': 80, 'URL': 250, '目录': 150}
        for col in columns:
            self.logs_tree.heading(col, text=col)
            self.logs_tree.column(col, width=col_widths.get(col, 100))
        
        # 添加滚动条
        scrollbar = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.logs_tree.yview)
        self.logs_tree.configure(yscrollcommand=scrollbar.set)
        
        self.logs_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # 绑定双击事件
        self.logs_tree.bind('<Double-1>', self.on_log_double_click)
    
    def create_debug_tab(self):
        """创建调试信息标签页"""
        debug_frame = ttk.Frame(self.notebook)
        self.notebook.add(debug_frame, text="调试信息")
        
        # 调试信息显示
        self.debug_text = scrolledtext.ScrolledText(
            debug_frame,
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.debug_text.pack(fill=tk.BOTH, expand=True)
        
        # 清空调试信息按钮
        clear_button = ttk.Button(debug_frame, text="清空调试信息", command=self.clear_debug)
        clear_button.pack(pady=5)
    
    def create_log_viewer_tab(self):
        """创建日志查看标签页"""
        log_frame = ttk.Frame(self.notebook)
        self.notebook.add(log_frame, text="日志查看")
        
        # 配置网格
        log_frame.grid_rowconfigure(1, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        
        # 工具栏
        toolbar = ttk.Frame(log_frame)
        toolbar.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        ttk.Label(toolbar, text="当前日志:").pack(side=tk.LEFT, padx=(0, 5))
        self.current_log_label = ttk.Label(toolbar, text="无", font=("Arial", 10, "bold"))
        self.current_log_label.pack(side=tk.LEFT, padx=(0, 20))
        
        ttk.Button(toolbar, text="复制内容", command=self.copy_log_content).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="保存到文件", command=self.save_log_content).pack(side=tk.LEFT, padx=5)
        ttk.Button(toolbar, text="在浏览器中打开", command=self.open_log_in_browser).pack(side=tk.LEFT, padx=5)
        
        # 搜索框
        search_frame = ttk.Frame(toolbar)
        search_frame.pack(side=tk.RIGHT)
        
        ttk.Label(search_frame, text="搜索:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="查找", command=self.search_in_log).pack(side=tk.LEFT)
        ttk.Button(search_frame, text="下一个", command=self.search_next).pack(side=tk.LEFT, padx=2)
        
        # 日志内容显示
        self.log_content_text = scrolledtext.ScrolledText(
            log_frame, 
            wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.log_content_text.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 绑定鼠标点击事件
        self.log_content_text.bind('<ButtonRelease-1>', self.update_line_number)
    
    def create_analysis_tab(self):
        """创建分析结果标签页"""
        analysis_frame = ttk.Frame(self.notebook)
        self.notebook.add(analysis_frame, text="分析结果")
        
        # 创建子标签页
        analysis_notebook = ttk.Notebook(analysis_frame)
        analysis_notebook.pack(fill=tk.BOTH, expand=True)
        
        # SQL查询分析
        sql_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(sql_frame, text="SQL查询")
        
        # SQL工具栏
        sql_toolbar = ttk.Frame(sql_frame)
        sql_toolbar.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        ttk.Label(sql_toolbar, text="SQL查询分析", font=("Arial", 10, "bold")).pack(side=tk.LEFT, padx=(0, 10))
        
        ttk.Button(sql_toolbar, text="导出所有SQL", command=self.export_sql_queries,
                  width=12).pack(side=tk.LEFT, padx=2)
        
        ttk.Button(sql_toolbar, text="分析表结构", command=self.analyze_tables,
                  width=12).pack(side=tk.LEFT, padx=2)
        
        # SQL查询显示
        self.sql_text = scrolledtext.ScrolledText(sql_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.sql_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=(5, 5))
        
        # 敏感信息
        sensitive_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(sensitive_frame, text="敏感信息")
        
        # 使用Treeview显示敏感信息
        sensitive_toolbar = ttk.Frame(sensitive_frame)
        sensitive_toolbar.pack(fill=tk.X, padx=5, pady=(5, 0))
        
        ttk.Label(sensitive_toolbar, text="敏感信息分析", font=("Arial", 10, "bold")).pack(side=tk.LEFT)
        
        # 创建Treeview显示敏感信息
        columns = ('类型', '值', '来源')
        self.sensitive_analysis_tree = ttk.Treeview(sensitive_frame, columns=columns, show='headings', height=10)
        
        # 设置列
        col_widths = {'类型': 80, '值': 200, '来源': 150}
        for col in columns:
            self.sensitive_analysis_tree.heading(col, text=col)
            self.sensitive_analysis_tree.column(col, width=col_widths.get(col, 100))
        
        scrollbar = ttk.Scrollbar(sensitive_frame, orient=tk.VERTICAL, command=self.sensitive_analysis_tree.yview)
        self.sensitive_analysis_tree.configure(yscrollcommand=scrollbar.set)
        
        self.sensitive_analysis_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=5)
        
        # 绑定双击事件
        self.sensitive_analysis_tree.bind('<Double-1>', self.on_sensitive_analysis_double_click)
        
        # 错误信息
        error_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(error_frame, text="错误信息")
        self.error_text = scrolledtext.ScrolledText(error_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.error_text.pack(fill=tk.BOTH, expand=True)
        
        # 摘要
        summary_frame = ttk.Frame(analysis_notebook)
        analysis_notebook.add(summary_frame, text="摘要")
        self.summary_text = scrolledtext.ScrolledText(summary_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.summary_text.pack(fill=tk.BOTH, expand=True)
    
    def create_stats_tab(self):
        """创建统计信息标签页"""
        stats_frame = ttk.Frame(self.notebook)
        self.notebook.add(stats_frame, text="统计信息")
        
        # 统计信息显示
        self.stats_text = scrolledtext.ScrolledText(stats_frame, wrap=tk.WORD, font=("Consolas", 9))
        self.stats_text.pack(fill=tk.BOTH, expand=True)
    
    def create_control_panel(self, parent):
        """创建右侧控制面板"""
        control_panel = ttk.LabelFrame(parent, text="扫描控制", padding="15")
        control_panel.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(5, 0))
        
        # URL输入
        url_frame = ttk.Frame(control_panel)
        url_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(url_frame, text="目标URL:").pack(anchor=tk.W)
        self.url_entry = ttk.Entry(url_frame)
        self.url_entry.pack(fill=tk.X, pady=(5, 0))
        self.url_entry.insert(0, "http://")
        
        # 代理设置
        proxy_frame = ttk.Frame(control_panel)
        proxy_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(proxy_frame, text="代理(可选):").pack(anchor=tk.W)
        self.proxy_entry = ttk.Entry(proxy_frame)
        self.proxy_entry.pack(fill=tk.X, pady=(5, 0))
        
        # 扫描选项
        options_frame = ttk.LabelFrame(control_panel, text="扫描选项", padding="10")
        options_frame.pack(fill=tk.X, pady=(0, 15))
        
        # 线程数
        ttk.Label(options_frame, text="线程数:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.threads_var = tk.StringVar(value="8")
        threads_spin = ttk.Spinbox(options_frame, from_=1, to=20, textvariable=self.threads_var, width=10)
        threads_spin.grid(row=0, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # 超时时间
        ttk.Label(options_frame, text="超时时间(秒):").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.StringVar(value="10")
        timeout_spin = ttk.Spinbox(options_frame, from_=1, to=30, textvariable=self.timeout_var, width=10)
        timeout_spin.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # 历史日志天数
        ttk.Label(options_frame, text="历史日志天数:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.days_var = tk.StringVar(value="365")
        days_spin = ttk.Spinbox(options_frame, from_=1, to=1000, textvariable=self.days_var, width=10)
        days_spin.grid(row=2, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # 输出选项
        ttk.Label(options_frame, text="输出详细程度:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.verbose_var = tk.StringVar(value="详细")
        verbose_combo = ttk.Combobox(options_frame, textvariable=self.verbose_var, 
                                    values=["简洁", "正常", "详细", "调试"], width=8, state="readonly")
        verbose_combo.grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # 控制按钮
        button_frame = ttk.Frame(control_panel)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="▶ 开始扫描", command=self.start_scan)
        self.start_btn.pack(fill=tk.X, pady=(0, 5))
        
        self.stop_btn = ttk.Button(button_frame, text="■ 停止扫描", command=self.stop_scan, 
                                  state=tk.DISABLED)
        self.stop_btn.pack(fill=tk.X, pady=(0, 5))
        
        ttk.Button(button_frame, text="📋 测试URL", command=self.test_url).pack(fill=tk.X, pady=(0, 5))
        
        # 进度条
        progress_frame = ttk.Frame(control_panel)
        progress_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X)
        
        self.progress_label = ttk.Label(progress_frame, text="0%")
        self.progress_label.pack()
    
    def create_status_bar(self, parent):
        """创建状态栏"""
        status_frame = ttk.Frame(parent, relief=tk.SUNKEN, borderwidth=1)
        status_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        
        # 状态标签
        self.status_var = tk.StringVar(value="就绪")
        status_label = ttk.Label(status_frame, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT, padx=10)
        
        # 扫描统计
        self.stats_var = tk.StringVar(value="日志: 0 | 错误: 0 | 目录: 0")
        stats_label = ttk.Label(status_frame, textvariable=self.stats_var)
        stats_label.pack(side=tk.RIGHT, padx=10)
    
    def update_status(self, message):
        """更新状态栏"""
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def update_progress(self, value, message=None):
        """更新进度条"""
        self.progress_var.set(value)
        self.progress_label.config(text=f"{int(value)}%")
        
        if message:
            self.update_status(message)
        
        self.root.update_idletasks()
    
    def log_realtime(self, message, tag=None):
        """记录实时日志"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        self.realtime_log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        
        if tag:
            start_index = f"{self.realtime_log_text.index('end-1c linestart')}"
            end_index = f"{self.realtime_log_text.index('end-1c')}"
            self.realtime_log_text.tag_add(tag, start_index, end_index)
        
        self.realtime_log_text.see(tk.END)
        self.root.update_idletasks()
    
    def log_debug(self, message):
        """记录调试信息"""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        
        self.debug_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.debug_text.see(tk.END)
        
        # 如果选择了调试模式，也在实时日志中显示
        if self.verbose_var.get() == "调试":
            self.log_realtime(message, "debug")
        
        self.root.update_idletasks()
    
    def update_stats(self):
        """更新统计信息"""
        found_count = len([log for log in self.found_logs if log.get('status') == 'success'])
        error_count = len([log for log in self.found_logs if log.get('status') == 'error'])
        
        # 统计目录数
        unique_dirs = set()
        for log in self.found_logs:
            url = log.get('url', '')
            if url:
                # 从URL中提取目录
                dir_match = re.search(r'(.+)/[^/]+$', url)
                if dir_match:
                    dir_path = dir_match.group(1)
                    unique_dirs.add(dir_path)
        
        dir_count = len(unique_dirs)
        
        self.stats_var.set(f"日志: {found_count} | 错误: {error_count} | 目录: {dir_count}")
        self.found_count_label.config(text=f"找到: {found_count}")
        self.error_count_label.config(text=f"错误: {error_count}")
    
    def scanner_callback(self, data):
        """扫描器回调函数"""
        message_type = data.get('type', 'info')
        message = data.get('message', '')
        
        if message_type == 'debug':
            self.log_debug(message)
        
        elif message_type == 'progress':
            value = data.get('value', 0)
            self.update_progress(value, message)
        
        elif message_type == 'progress_detail':
            value = data.get('value', 0)
            total = data.get('total', 100)
            percent = int((value / total) * 100) if total > 0 else 0
            self.progress_var.set(percent)
            self.progress_label.config(text=f"{percent}%")
            self.log_realtime(message, 'info')
        
        elif message_type == 'info':
            self.log_realtime(message, 'info')
        
        elif message_type == 'detail':
            # 根据详细程度设置决定是否显示detail信息
            verbose = self.verbose_var.get()
            if verbose in ["详细", "调试"]:
                self.log_realtime(message, 'detail')
            elif verbose == "正常" and "尝试:" not in message and "生成" not in message:
                self.log_realtime(message, 'detail')
        
        elif message_type == 'date_scan':
            date = data.get('date')
            if date:
                self.current_dir_label.config(text=f"当前日期: {date.strftime('%Y-%m-%d')}")
            self.log_realtime(message, 'date_scan')
        
        elif message_type == 'success':
            self.log_realtime(message, 'success')
        
        elif message_type == 'error':
            self.log_realtime(message, 'error')
        
        elif message_type == 'found':
            log = data.get('log')
            if log:
                self.found_logs.append(log)
                self.add_log_to_tree(log)
                self.log_realtime(message, 'found')
    
    def add_log_to_tree(self, log):
        """添加日志到Treeview"""
        # 从URL中提取目录
        url = log.get('url', '')
        directory = '未知'
        if url:
            dir_match = re.search(r'(.+)/[^/]+$', url)
            if dir_match:
                directory = dir_match.group(1)
                # 只保留相对路径部分
                if directory.startswith('http'):
                    # 提取路径部分
                    parsed = urlparse(directory)
                    directory = parsed.path
                    if not directory:
                        directory = '/'
        
        if log.get('status') == 'success':
            values = (
                log.get('filename', ''),
                f"{log.get('size', 0):,} 字节",
                log.get('lines', 0),
                '✓ 成功',
                log.get('url', '')[:40] + '...' if len(log.get('url', '')) > 40 else log.get('url', ''),
                directory[:30] + '...' if len(directory) > 30 else directory
            )
            item_id = self.logs_tree.insert('', tk.END, values=values, tags=('success',))
        else:
            values = (
                log.get('filename', ''),
                'N/A',
                'N/A',
                f'✗ {log.get("error", "错误")}',
                log.get('url', '')[:40] + '...' if len(log.get('url', '')) > 40 else log.get('url', ''),
                directory[:30] + '...' if len(directory) > 30 else directory
            )
            item_id = self.logs_tree.insert('', tk.END, values=values, tags=('error',))
        
        # 存储原始数据到映射字典
        self.tree_item_data[item_id] = log
        
        # 滚动到最新项
        self.logs_tree.see(item_id)
        
        # 更新统计
        self.update_stats()
    
    def on_log_double_click(self, event):
        """双击日志项"""
        selection = self.logs_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        
        # 从映射字典中获取log数据
        if item_id in self.tree_item_data:
            log = self.tree_item_data[item_id]
            if log.get('status') == 'success':
                self.display_log_content(log)
                filename = log.get('filename', '未知')
                self.current_log_label.config(text=filename)
                # 切换到日志查看标签页
                self.notebook.select(1)
    
    def display_log_content(self, log):
        """显示日志内容"""
        content = log.get('content', '')
        self.log_content_text.delete(1.0, tk.END)
        self.log_content_text.insert(1.0, content)
        
        # 更新行号显示
        self.update_line_number()
        
        # 语法高亮
        self.highlight_log_content()
    
    def update_line_number(self, event=None):
        """更新当前行号显示"""
        try:
            # 获取当前光标位置
            cursor_index = self.log_content_text.index(tk.INSERT)
            line_num = int(cursor_index.split('.')[0])
        except:
            line_num = 0
    
    def highlight_log_content(self):
        """高亮日志内容"""
        content = self.log_content_text.get(1.0, tk.END)
        
        # 移除旧的高亮
        for tag in ['timestamp', 'error', 'sql', 'ip', 'url', 'password', 'highlight']:
            self.log_content_text.tag_remove(tag, 1.0, tk.END)
        
        # 高亮时间戳
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}',
        ]
        
        for pattern in timestamp_patterns:
            self.highlight_pattern(pattern, 'timestamp', 'orange')
        
        # 高亮错误信息
        error_patterns = [
            r'ERROR.*',
            r'error.*',
            r'Exception.*',
            r'Warning.*',
        ]
        
        for pattern in error_patterns:
            self.highlight_pattern(pattern, 'error', 'red')
        
        # 高亮SQL语句
        sql_pattern = r'SQL\s*[:：]\s*(.*?)(?:\n|$)'
        self.highlight_pattern(sql_pattern, 'sql', 'blue')
        
        # 高亮IP地址
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        self.highlight_pattern(ip_pattern, 'ip', 'green')
        
        # 高亮URL
        url_pattern = r'https?://[^\s<>"\']+'
        self.highlight_pattern(url_pattern, 'url', 'purple')
        
        # 高亮密码和敏感信息
        sensitive_patterns = [
            (r'(?:password|passwd|pwd)\s*[:=]\s*[\'"]?([^\s\'\"]+)[\'"]?', 'password'),
            (r'(?:token|auth|session)\s*[:=]\s*[\'"]?([^\s\'\"]{10,})[\'"]?', 'password'),
            (r'(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*[\'"]?([^\s\'\"]{10,})[\'"]?', 'password'),
        ]
        
        for pattern, tag in sensitive_patterns:
            self.highlight_pattern(pattern, 'password', 'red', font_weight='bold')
    
    def highlight_pattern(self, pattern, tag, color, font_weight='normal'):
        """高亮匹配的模式"""
        start = '1.0'
        while True:
            match_len = tk.IntVar(value=0)
            start = self.log_content_text.search(
                pattern, start, stopindex=tk.END, regexp=True, count=match_len
            )
            if not start or match_len.get() == 0:
                break
            
            end = f"{start}+{match_len.get()}c"
            self.log_content_text.tag_add(tag, start, end)
            font_spec = ("Consolas", 9, font_weight) if font_weight == 'bold' else ("Consolas", 9)
            self.log_content_text.tag_config(tag, foreground=color, font=font_spec)
            
            start = end
    
    def search_in_log(self):
        """在日志中搜索"""
        search_text = self.search_var.get()
        if not search_text:
            return
        
        # 移除旧的高亮
        self.log_content_text.tag_remove('highlight', 1.0, tk.END)
        
        # 搜索并高亮
        start = '1.0'
        count = 0
        while True:
            start = self.log_content_text.search(search_text, start, stopindex=tk.END, nocase=True)
            if not start:
                break
            
            end = f"{start}+{len(search_text)}c"
            self.log_content_text.tag_add('highlight', start, end)
            self.log_content_text.tag_config('highlight', background='yellow', foreground='black')
            
            # 滚动到第一个匹配项
            if count == 0:
                self.log_content_text.see(start)
            
            start = end
            count += 1
        
        if count > 0:
            messagebox.showinfo("搜索结果", f"找到 {count} 个匹配项")
        else:
            messagebox.showinfo("搜索结果", "未找到匹配项")
    
    def search_next(self):
        """查找下一个"""
        # 简化实现，重新搜索
        self.search_in_log()
    
    def start_scan(self):
        """开始扫描"""
        if self.scanning:
            return
        
        url = self.url_entry.get().strip()
        if not url or url == "http://":
            messagebox.showerror("错误", "请输入目标URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # 设置代理
        proxy = self.proxy_entry.get().strip()
        if proxy:
            self.scanner.set_proxy(proxy)
        
        # 设置扫描参数
        try:
            threads = int(self.threads_var.get())
            self.scanner.max_workers = max(1, min(threads, 20))
            
            timeout = int(self.timeout_var.get())
            self.scanner.timeout = timeout
            
            # 设置历史日志天数
            history_days = int(self.days_var.get())
            self.scanner.history_days = history_days
            
        except:
            pass
        
        # 清空之前的结果
        self.clear_results()
        
        # 设置回调函数
        self.scanner.set_callback(self.scanner_callback)
        
        # 更新UI状态
        self.scanning = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.update_status("正在准备扫描...")
        self.update_progress(0)
        
        # 启动扫描线程
        self.scan_thread = threading.Thread(target=self.do_scan, args=(url,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
    
    def do_scan(self, url):
        """执行扫描"""
        try:
            # 设置扫描状态
            self.scanner.scanning = True
            self.scanner.found_logs = []
            self.scanner.request_count = 0
            self.scanner.success_count = 0
            self.scanner.failed_count = 0
            
            # 1. 查找日志目录
            self.root.after(0, lambda: self.log_realtime("正在查找日志目录...", 'info'))
            directories = self.scanner.find_log_directory(url)
            
            if not directories:
                self.root.after(0, lambda: self.log_realtime("未找到日志目录", 'error'))
                self.root.after(0, lambda: self.update_status("扫描完成 - 未找到日志目录"))
                self.root.after(0, lambda: self.update_progress(100))
                
                # 显示请求统计
                stats = f"请求统计: 总数={self.scanner.request_count}, 成功={self.scanner.success_count}, 失败={self.scanner.failed_count}"
                self.root.after(0, lambda: self.log_realtime(stats, 'info'))
            else:
                # 2. 扫描日志文件
                if isinstance(directories, list):
                    self.root.after(0, lambda: self.log_realtime(f"找到 {len(directories)} 个日志目录:", 'success'))
                    for dir_path in directories:
                        self.root.after(0, lambda d=dir_path: self.log_realtime(f"  - {d}", 'success'))
                else:
                    self.root.after(0, lambda: self.log_realtime(f"找到日志目录: {directories}", 'success'))
                
                self.root.after(0, lambda: self.log_realtime("开始扫描日志文件...", 'info'))
                
                # directory 现在是一个列表，包含多个目录
                if isinstance(directories, list):
                    found_logs = self.scanner.scan_log_files_in_directory(url, directories)
                else:
                    found_logs = self.scanner.scan_log_files_in_directory(url, [directories])
                
                # 3. 分析日志
                if found_logs:
                    self.root.after(0, lambda: self.log_realtime(f"扫描完成，共找到 {len(found_logs)} 个日志文件", 'success'))
                    self.root.after(0, lambda: self.analyze_logs(found_logs))
                else:
                    self.root.after(0, lambda: self.log_realtime("未找到任何日志文件", 'error'))
                
                # 显示请求统计
                stats = f"请求统计: 总数={self.scanner.request_count}, 成功={self.scanner.success_count}, 失败={self.scanner.failed_count}"
                self.root.after(0, lambda: self.log_realtime(stats, 'info'))
            
            self.root.after(0, lambda: self.update_status("扫描完成"))
            self.root.after(0, lambda: self.update_progress(100))
            
        except Exception as e:
            self.root.after(0, lambda: self.log_realtime(f"扫描出错: {str(e)}", 'error'))
            self.root.after(0, lambda: messagebox.showerror("错误", f"扫描过程中出现错误:\n{str(e)}"))
        
        finally:
            # 恢复UI状态
            self.root.after(0, lambda: self.scanning_finished())
    
    def scanning_finished(self):
        """扫描完成"""
        self.scanning = False
        self.scanner.scanning = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.current_dir_label.config(text="当前目录: 无")
    
    def stop_scan(self):
        """停止扫描"""
        if self.scanning:
            self.scanner.stop_scan()
            self.log_realtime("正在停止扫描...", 'info')
            self.update_status("正在停止...")
    
    def analyze_logs(self, logs):
        """分析日志"""
        try:
            all_analysis = {
                'sql_queries': [],
                'sensitive_data': [],
                'errors': [],
                'ip_addresses': [],
                'urls': [],
                'emails': [],
                'summary': {}
            }
            
            # 显示分析进度
            self.log_realtime("开始分析日志内容...", 'info')
            
            for i, log in enumerate(logs):
                if log.get('status') == 'success':
                    content = log.get('content', '')
                    log_url = log.get('url', '')
                    filename = log.get('filename', '')
                    
                    # 分析内容
                    analysis = self.analyze_log_content(content, log_url, filename, log)
                    
                    # 合并结果
                    for key in ['sql_queries', 'sensitive_data', 'errors', 'ip_addresses', 'urls', 'emails']:
                        if key in analysis:
                            all_analysis[key].extend(analysis[key])
                    
                    # 更新进度
                    progress = 80 + (i * 20 // len(logs))
                    self.update_progress(progress, f"分析日志 {i+1}/{len(logs)}")
            
            # 生成摘要
            all_analysis['summary'] = self.generate_summary(all_analysis)
            self.current_analysis = all_analysis
            
            # 显示分析结果
            self.display_analysis_results(all_analysis)
            
            # 显示统计信息
            self.display_stats(all_analysis)
            
            self.log_realtime("分析完成", 'success')
            
        except Exception as e:
            self.log_realtime(f"分析出错: {str(e)}", 'error')
    
    def analyze_log_content(self, content, log_url, filename, log):
        """分析日志内容"""
        analysis = {
            'sql_queries': [],
            'sensitive_data': [],
            'errors': [],
            'ip_addresses': [],
            'urls': [],
            'emails': []
        }
        
        # 提取SQL查询
        sql_patterns = [
            r'SQL\s*[:：]\s*(.*?)(?:\n|$)',
            r'\[\s*sql\s*\]\s*(.*?)(?:\n|$)',
            r'execute\s*[:：]\s*(.*?)(?:\n|$)',
            r'query\s*[:：]\s*(.*?)(?:\n|$)',
        ]
        
        for pattern in sql_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                sql = match.strip()
                if sql and len(sql) > 10:
                    analysis['sql_queries'].append(sql)
        
        # 提取敏感信息
        patterns = [
            (r'(?:password|passwd|pwd)\s*[:=]\s*[\'"]?([^\s\'\"]+)[\'"]?', "密码"),
            (r'(?:token|auth|session)\s*[:=]\s*[\'"]?([^\s\'\"]{10,})[\'"]?', "令牌"),
            (r'(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*[\'"]?([^\s\'\"]{10,})[\'"]?', "API密钥"),
        ]
        
        for pattern, data_type in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    value = match[0]
                else:
                    value = match
                
                if value and len(value.strip()) > 3:
                    sensitive_item = {
                        'type': data_type,
                        'value': value.strip(),
                        'source': filename
                    }
                    analysis['sensitive_data'].append(sensitive_item)
        
        # 提取错误信息
        error_patterns = [
            r'ERROR.*?(?:\n|$)',
            r'error.*?(?:\n|$)',
            r'Exception.*?(?:\n|$)',
            r'Warning.*?(?:\n|$)',
        ]
        
        for pattern in error_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if match:
                    analysis['errors'].append(match)
        
        # 提取IP地址
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_addresses = re.findall(ip_pattern, content)
        analysis['ip_addresses'] = ip_addresses
        
        # 提取URL
        url_pattern = r'https?://[^\s<>"\']+'
        urls = re.findall(url_pattern, content)
        analysis['urls'] = urls
        
        # 提取邮箱
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, content)
        analysis['emails'] = emails
        
        return analysis
    
    def generate_summary(self, analysis):
        """生成摘要"""
        return {
            'sql_query_count': len(analysis['sql_queries']),
            'sensitive_data_count': len(analysis['sensitive_data']),
            'error_count': len(analysis['errors']),
            'unique_ips': len(set(analysis['ip_addresses'])),
            'url_count': len(analysis['urls']),
            'email_count': len(analysis['emails'])
        }
    
    def display_analysis_results(self, analysis):
        """显示分析结果"""
        # SQL查询
        self.sql_text.delete(1.0, tk.END)
        if analysis['sql_queries']:
            unique_queries = list(set(analysis['sql_queries']))
            self.sql_text.insert(tk.END, f"共发现 {len(unique_queries)} 条SQL查询:\n\n")
            for i, query in enumerate(unique_queries[:50], 1):
                self.sql_text.insert(tk.END, f"{i}. {query[:200]}\n\n")
            
            if len(unique_queries) > 50:
                self.sql_text.insert(tk.END, f"... 还有 {len(unique_queries) - 50} 条未显示\n")
        else:
            self.sql_text.insert(tk.END, "未发现SQL查询\n")
        
        # 敏感信息 - 使用Treeview显示
        self.sensitive_analysis_tree.delete(*self.sensitive_analysis_tree.get_children())
        if analysis['sensitive_data']:
            for item in analysis['sensitive_data']:
                if isinstance(item, dict):
                    self.sensitive_analysis_tree.insert('', tk.END, values=(item.get('type', '未知'), 
                                                                          item.get('value', ''), 
                                                                          item.get('source', '')))
        else:
            self.sensitive_analysis_tree.insert('', tk.END, values=("无", "未发现敏感信息", ""))
        
        # 错误信息
        self.error_text.delete(1.0, tk.END)
        if analysis['errors']:
            unique_errors = list(set(analysis['errors']))[:50]
            self.error_text.insert(tk.END, f"共发现 {len(unique_errors)} 条错误信息:\n\n")
            for i, error in enumerate(unique_errors, 1):
                self.error_text.insert(tk.END, f"{i}. {error[:200]}\n\n")
        else:
            self.error_text.insert(tk.END, "未发现错误信息\n")
        
        # 摘要
        self.summary_text.delete(1.0, tk.END)
        
        summary = f"""
{'='*50} 扫描结果摘要 {'='*50}

基本统计:
• SQL查询数量: {analysis['summary']['sql_query_count']}
• 敏感信息数量: {analysis['summary']['sensitive_data_count']}
• 错误信息数量: {analysis['summary']['error_count']}
• 发现的IP地址: {analysis['summary']['unique_ips']}
• 发现的URL: {analysis['summary']['url_count']}
• 发现的邮箱: {analysis['summary']['email_count']}

风险评估:
{self.assess_risk(analysis)}

建议:
{self.get_recommendations(analysis)}

{'='*110}
"""
        
        self.summary_text.insert(1.0, summary)
    
    def display_stats(self, analysis):
        """显示统计信息"""
        self.stats_text.delete(1.0, tk.END)
        
        stats_text = f"""
{'='*50} 统计信息 {'='*50}

扫描概览:
• 总扫描日志数: {len(self.found_logs)}
• 成功下载: {len([log for log in self.found_logs if log.get('status') == 'success'])}
• 下载失败: {len([log for log in self.found_logs if log.get('status') == 'error'])}
• HTTP请求统计: 总数={self.scanner.request_count}, 成功={self.scanner.success_count}, 失败={self.scanner.failed_count}

内容分析:
• SQL查询: {analysis['summary']['sql_query_count']}
• 敏感信息: {analysis['summary']['sensitive_data_count']}
• 错误信息: {analysis['summary']['error_count']}
• 唯一IP地址: {analysis['summary']['unique_ips']}
• URL数量: {analysis['summary']['url_count']}
• 邮箱地址: {analysis['summary']['email_count']}

文件统计:
"""
        
        # 按大小排序的日志文件
        success_logs = [log for log in self.found_logs if log.get('status') == 'success']
        if success_logs:
            sorted_logs = sorted(success_logs, key=lambda x: x.get('size', 0), reverse=True)
            
            stats_text += "\n文件大小排名 (前10):\n"
            for i, log in enumerate(sorted_logs[:10], 1):
                filename = log.get('filename', '未知')
                size = log.get('size', 0)
                lines = log.get('lines', 0)
                stats_text += f"{i}. {filename} - {size:,} 字节 ({lines} 行)\n"
        
        self.stats_text.insert(1.0, stats_text)
    
    def assess_risk(self, analysis):
        """风险评估"""
        risks = []
        
        if analysis['sensitive_data']:
            sensitive_count = len(analysis['sensitive_data'])
            risks.append(f"⚠️ 发现 {sensitive_count} 条敏感信息泄露 (高风险)")
        
        if len(analysis['sql_queries']) > 50:
            risks.append(f"⚠️ 发现 {len(analysis['sql_queries'])} 条SQL查询，可能包含敏感操作")
        
        if len(analysis['errors']) > 10:
            risks.append(f"⚠️ 发现 {len(analysis['errors'])} 条错误信息，可能暴露系统信息")
        
        unique_ips = len(set(analysis['ip_addresses']))
        if unique_ips > 100:
            risks.append(f"⚠️ 发现 {unique_ips} 个IP地址，可能存在访问日志")
        
        if not risks:
            return "✅ 未发现高风险问题"
        
        return "\n".join(risks)
    
    def get_recommendations(self, analysis):
        """获取建议"""
        recommendations = []
        
        if analysis['sensitive_data']:
            recommendations.append("• 立即更改泄露的密码和密钥")
            recommendations.append("• 检查数据库访问日志")
            recommendations.append("• 实施更严格的访问控制")
        
        if analysis['sql_queries']:
            recommendations.append("• 检查SQL语句中是否包含敏感操作")
            recommendations.append("• 审查数据库权限设置")
        
        if len(analysis['errors']) > 5:
            recommendations.append("• 修复日志中出现的错误")
            recommendations.append("• 关闭生产环境的调试模式")
        
        recommendations.append("• 定期检查日志文件权限")
        recommendations.append("• 确保日志目录不可通过Web访问")
        recommendations.append("• 定期清理旧日志文件")
        
        return "\n".join(recommendations)
    
    def clear_results(self):
        """清空结果"""
        # 清空实时日志
        self.realtime_log_text.delete(1.0, tk.END)
        
        # 清空日志列表
        for item in self.logs_tree.get_children():
            self.logs_tree.delete(item)
        
        # 清空日志内容
        self.log_content_text.delete(1.0, tk.END)
        self.current_log_label.config(text="无")
        
        # 清空分析结果
        self.sql_text.delete(1.0, tk.END)
        self.sensitive_analysis_tree.delete(*self.sensitive_analysis_tree.get_children())
        self.error_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        
        # 清空Treeview数据映射
        self.tree_item_data.clear()
        
        # 重置进度和状态
        self.update_progress(0)
        self.update_status("就绪")
        self.current_dir_label.config(text="当前目录: 无")
        
        # 清空数据
        self.found_logs = []
        self.current_analysis = None
        
        # 更新统计
        self.update_stats()
    
    def clear_debug(self):
        """清空调试信息"""
        self.debug_text.delete(1.0, tk.END)
    
    def toggle_debug(self):
        """切换调试模式"""
        if self.verbose_var.get() == "调试":
            self.verbose_var.set("详细")
        else:
            self.verbose_var.set("调试")
            self.notebook.select(2)  # 切换到调试标签页
    
    def copy_log_content(self):
        """复制日志内容到剪贴板"""
        content = self.log_content_text.get(1.0, tk.END)
        if content.strip():
            self.root.clipboard_clear()
            self.root.clipboard_append(content)
            messagebox.showinfo("成功", "日志内容已复制到剪贴板")
    
    def on_sensitive_analysis_double_click(self, event):
        """双击分析结果中的敏感信息"""
        selection = self.sensitive_analysis_tree.selection()
        if not selection:
            return
        
        item_id = selection[0]
        
        # 获取值
        item_data = self.sensitive_analysis_tree.item(item_id, 'values')
        if len(item_data) >= 2:
            value = item_data[1]
            messagebox.showinfo("敏感信息详情", f"值: {value}")
    
    def save_log_content(self):
        """保存日志内容到文件"""
        content = self.log_content_text.get(1.0, tk.END)
        if content.strip():
            filename = filedialog.asksaveasfilename(
                defaultextension=".log",
                filetypes=[("日志文件", "*.log"), ("文本文件", "*.txt"), ("所有文件", "*.*")]
            )
            if filename:
                try:
                    with open(filename, 'w', encoding='utf-8') as f:
                        f.write(content)
                    messagebox.showinfo("成功", f"日志已保存到: {filename}")
                except Exception as e:
                    messagebox.showerror("错误", f"保存失败: {str(e)}")
    
    def open_log_in_browser(self):
        """在浏览器中打开当前日志URL"""
        selection = self.logs_tree.selection()
        if not selection:
            messagebox.showwarning("警告", "请先选择一个日志")
            return
        
        item_id = selection[0]
        
        # 从映射字典中获取log数据
        if item_id in self.tree_item_data:
            log = self.tree_item_data[item_id]
            url = log.get('url')
            if url:
                webbrowser.open(url)
            else:
                messagebox.showwarning("警告", "该日志没有URL")
    
    def test_url(self):
        """测试URL连接"""
        url = self.url_entry.get().strip()
        if not url or url == "http://":
            messagebox.showerror("错误", "请输入要测试的URL")
            return
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        try:
            response = requests.get(url, timeout=5, verify=False)
            messagebox.showinfo("连接测试", 
                              f"URL: {url}\n"
                              f"状态码: {response.status_code}\n"
                              f"响应时间: {response.elapsed.total_seconds():.2f}秒")
        except Exception as e:
            messagebox.showerror("连接测试", f"连接失败: {str(e)}")
    
    def export_report(self):
        """导出扫描报告"""
        if not self.found_logs:
            messagebox.showwarning("警告", "没有扫描结果可以导出")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")]
        )
        
        if filename:
            try:
                report = self.generate_report()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(report)
                messagebox.showinfo("成功", f"报告已导出到: {filename}")
            except Exception as e:
                messagebox.showerror("错误", f"导出失败: {str(e)}")
    
    def generate_report(self):
        """生成扫描报告"""
        report = []
        report.append("=" * 80)
        report.append("ThinkPHP日志扫描报告 v1.0.0")
        report.append(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"目标URL: {self.url_entry.get()}")
        report.append("=" * 80)
        report.append("")
        
        # 扫描结果
        report.append("扫描结果:")
        report.append("-" * 40)
        
        # 按目录分组显示
        logs_by_dir = {}
        for log in self.found_logs:
            url = log.get('url', '')
            directory = '未知'
            if url:
                dir_match = re.search(r'(.+)/[^/]+$', url)
                if dir_match:
                    directory = dir_match.group(1)
            
            if directory not in logs_by_dir:
                logs_by_dir[directory] = []
            logs_by_dir[directory].append(log)
        
        for directory, logs in logs_by_dir.items():
            report.append(f"目录: {directory}")
            for log in logs:
                if log.get('status') == 'success':
                    report.append(f"  ✓ {log.get('filename')} - {log.get('size'):,} 字节")
                else:
                    report.append(f"  ✗ {log.get('filename')} - {log.get('error')}")
            report.append("")
        
        # 分析结果
        if self.current_analysis:
            report.append("分析结果:")
            report.append("-" * 40)
            summary = self.current_analysis.get('summary', {})
            report.append(f"SQL查询数量: {summary.get('sql_query_count', 0)}")
            report.append(f"敏感信息数量: {summary.get('sensitive_data_count', 0)}")
            report.append(f"错误信息数量: {summary.get('error_count', 0)}")
            report.append(f"唯一IP地址: {summary.get('unique_ips', 0)}")
            report.append("")
            
            # 风险评估
            report.append("风险评估:")
            report.append("-" * 40)
            report.append(self.assess_risk(self.current_analysis))
            report.append("")
            
            # 建议
            report.append("建议:")
            report.append("-" * 40)
            report.append(self.get_recommendations(self.current_analysis))
        
        return "\n".join(report)
    
    def export_sql_queries(self):
        """导出所有SQL查询到文件"""
        if not self.current_analysis or not self.current_analysis.get('sql_queries'):
            messagebox.showwarning("警告", "没有SQL查询可以导出")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".sql",
            filetypes=[("SQL文件", "*.sql"), ("文本文件", "*.txt"), ("所有文件", "*.*")],
            initialfile="thinkphp_sql_queries"
        )
        
        if filename:
            try:
                sql_queries = self.current_analysis.get('sql_queries', [])
                unique_queries = list(set(sql_queries))
                
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"-- ThinkPHP SQL查询导出\n")
                    f.write(f"-- 导出时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"-- 目标URL: {self.url_entry.get()}\n")
                    f.write(f"-- 共找到 {len(sql_queries)} 条SQL查询，去重后 {len(unique_queries)} 条\n")
                    f.write("=" * 80 + "\n\n")
                    
                    for i, query in enumerate(unique_queries, 1):
                        f.write(f"-- 查询 {i}\n")
                        f.write(query + "\n\n")
                
                messagebox.showinfo("成功", f"SQL查询已导出到:\n{filename}\n\n"
                                         f"总查询数: {len(sql_queries)}\n"
                                         f"去重后: {len(unique_queries)}")
                
                # 询问是否打开文件
                if messagebox.askyesno("打开文件", "是否打开导出的SQL文件？"):
                    try:
                        os.startfile(filename)
                    except:
                        import subprocess
                        subprocess.call(['open', filename])
                        
            except Exception as e:
                messagebox.showerror("错误", f"导出SQL查询失败: {str(e)}")
    
    def analyze_tables(self):
        """分析数据库表结构"""
        if not self.current_analysis:
            messagebox.showwarning("警告", "请先扫描并分析日志")
            return
        
        sql_queries = self.current_analysis.get('sql_queries', [])
        if not sql_queries:
            messagebox.showwarning("警告", "没有找到SQL查询")
            return
        
        # 提取表名和列名
        tables = defaultdict(set)  # 表名 -> 列名集合
        
        # 更复杂的表名和列名提取模式
        patterns = [
            # FROM table
            (r'\bFROM\s+([a-z_][a-z0-9_]*)\b', 'table'),
            # SELECT column FROM
            (r'\bSELECT\s+(.+?)\bFROM\s+([a-z_][a-z0-9_]*)', 'columns'),
            # INSERT INTO table (col1, col2)
            (r'\bINSERT\s+INTO\s+([a-z_][a-z0-9_]*)\s*\((.*?)\)', 'insert_cols'),
            # UPDATE table SET col1=val1
            (r'\bUPDATE\s+([a-z_][a-z0-9_]*)\s+SET\s+(.*?)(?:\s+WHERE|$)', 'update_cols'),
        ]
        
        for query in sql_queries:
            query_lower = query.lower()
            
            for pattern, pattern_type in patterns:
                matches = re.findall(pattern, query_lower, re.IGNORECASE | re.DOTALL)
                
                for match in matches:
                    if pattern_type == 'table':
                        table_name = match
                        tables[table_name]  # 确保表名存在
                    
                    elif pattern_type == 'columns':
                        columns_part, table_name = match
                        # 解析列名
                        columns = re.split(r'\s*,\s*', columns_part)
                        for col in columns:
                            # 移除别名等
                            col = re.sub(r'\s+as\s+.*$', '', col, flags=re.IGNORECASE)
                            col = re.sub(r'\s+.*$', '', col)  # 移除函数等
                            if col.strip():
                                tables[table_name].add(col.strip())
                    
                    elif pattern_type == 'insert_cols':
                        table_name, columns_part = match
                        columns = re.split(r'\s*,\s*', columns_part)
                        for col in columns:
                            if col.strip():
                                tables[table_name].add(col.strip())
                    
                    elif pattern_type == 'update_cols':
                        table_name, set_part = match
                        # 解析SET子句中的列名
                        assignments = re.split(r'\s*,\s*', set_part)
                        for assign in assignments:
                            col_match = re.match(r'([a-z_][a-z0-9_]*)\s*=.*', assign, re.IGNORECASE)
                            if col_match:
                                tables[table_name].add(col_match.group(1))
        
        # 显示结果
        result = "数据库表结构分析\n"
        result += "=" * 50 + "\n\n"
        
        if not tables:
            result += "未识别出数据库表结构\n"
        else:
            result += f"共发现 {len(tables)} 个表:\n\n"
            
            for table_name, columns in sorted(tables.items()):
                result += f"表: {table_name}\n"
                result += f"  列数: {len(columns)}\n"
                if columns:
                    result += "  列名: " + ", ".join(sorted(columns)) + "\n"
                result += "\n"
        
        # 在新窗口中显示结果
        self.show_analysis_window("数据库表结构分析", result)
    
    def show_analysis_window(self, title, content):
        """在新窗口中显示分析结果"""
        window = tk.Toplevel(self.root)
        window.title(title)
        window.geometry("600x400")
        
        # 工具栏
        toolbar = ttk.Frame(window)
        toolbar.pack(fill=tk.X, padx=10, pady=(10, 0))
        
        ttk.Button(toolbar, text="复制内容", 
                  command=lambda: self.copy_to_clipboard(content)).pack(side=tk.LEFT, padx=2)
        
        # 内容显示
        text = scrolledtext.ScrolledText(window, wrap=tk.WORD, font=("Consolas", 9))
        text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        text.insert(1.0, content)
        text.config(state=tk.DISABLED)
    
    def copy_to_clipboard(self, content):
        """复制内容到剪贴板"""
        self.root.clipboard_clear()
        self.root.clipboard_append(content)
        messagebox.showinfo("成功", "内容已复制到剪贴板")
    
    def show_help(self):
        """显示帮助信息"""
        help_text = """
ThinkPHP日志扫描器 v1.0.0 使用帮助

主要功能:
• 支持多目录扫描: 自动发现并扫描所有ThinkPHP日志目录
• 智能日期格式检测: 支持多种ThinkPHP日期格式
• SQL查询导出: 导出所有发现的SQL查询
• 详细分析: 敏感信息、错误信息、IP地址等提取
• 风险评估: 自动评估安全风险并提供建议
• 多种导出格式: 支持报告、SQL文件、文本文件导出

基本使用:
1. 输入目标URL，点击"开始扫描"按钮
2. 扫描过程中可以实时查看找到的日志
3. 双击日志项可以查看详细内容
4. 扫描完成后会自动分析日志内容
5. 使用导出功能保存扫描结果

扫描选项:
• 线程数: 控制并发扫描的线程数量(1-20)
• 超时时间: 设置请求超时时间(1-30秒)
• 历史日志天数: 扫描历史日志的天数范围
• 输出详细程度: 控制扫描过程中的输出信息量

使用技巧:
• 扫描过程中可以随时停止
• 可以导出多种格式的报告
• 可以保存单个日志内容
• 支持代理设置
• 双击日志项可快速查看内容

安全提示:
• 仅用于授权的安全测试
• 遵守相关法律法规
• 未经授权请勿扫描他人系统
• 导出文件请妥善保管
"""
        
        messagebox.showinfo("帮助", help_text)
    
    def on_closing(self):
        """关闭程序"""
        if self.scanning:
            if messagebox.askyesno("确认", "扫描正在进行中，确定要退出吗？"):
                self.scanner.stop_scan()
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """运行程序"""
        # 居中显示窗口
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
        
        self.root.mainloop()


def main():
    """主函数"""
    # 显示免责声明
    print("=" * 60)
    print("ThinkPHP日志扫描器 v1.0.0")
    print("仅用于授权的安全测试和教育目的")
    print("未经授权使用本工具是非法行为")
    print("=" * 60)
    print()
    
    # 创建并运行GUI
    app = ScannerGUI()
    app.run()


if __name__ == "__main__":
    main()