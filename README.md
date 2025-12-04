# ThinkPHP日志扫描器 v1.0.0

## 简介
这是一个用于扫描ThinkPHP日志文件的工具，可以帮助安全研究人员检测ThinkPHP网站中可能存在的日志泄露问题。

## 功能特性
- 支持多目录智能扫描
- 智能日期格式检测
- 支持ThinkPHP 3.x/5.x/6.x版本
- 自动分析日志内容
- SQL查询提取与分析
- 敏感信息检测
- 图形用户界面（GUI）
- 支持代理设置
- 导出扫描报告

## 系统要求
- Python 3.6+
- Windows/Linux/macOS

## 安装依赖
```bash
pip install -r requirements.txt
```
## 快速开始
1. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
2. 运行程序：
   ```bash
   python thinkphp_log_scanner.py
   ```