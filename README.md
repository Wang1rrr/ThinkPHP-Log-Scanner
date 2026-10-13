# ThinkPHP日志扫描器 v1.0.0

## 简介
这是一个用于扫描 ThinkPHP 日志文件的工具，可以帮助安全研究人员检测 ThinkPHP 网站中可能存在的日志泄露问题。

## 功能特性
- 支持多目录智能扫描
- 智能日期格式检测
- 支持 ThinkPHP 3.x / 5.x / 6.x 版本
- 自动分析日志内容
- SQL 查询提取与分析
- 敏感信息检测
- 图形用户界面（GUI）
- 支持代理设置
- 导出扫描报告

## 系统要求
- Python 3.8+
- Windows / Linux / macOS
- Python 环境需包含 Tkinter 图形界面支持。

## 安装为命令行启动程序
在仓库根目录运行：
```bash
python -m pip install .
```

安装完成后可使用以下命令启动图形界面：
```bash
thinkphp-scanner
```

如果直接运行源码，可按下方步骤安装依赖并启动。

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
   或在 Windows 中通过双击相应启动脚本运行（如果已配置关联）。

## 使用说明
1. 在主界面输入目标 URL（如 `http://example.com/`）。
2. 根据需要设置扫描参数（线程数、历史天数、代理等，可选）。
3. 点击 **“开始扫描”** 按钮，等待扫描完成。
4. 在结果面板中查看：
   - 已发现的日志文件列表
   - 日志内容预览
   - 自动分析结果（SQL、敏感信息等）
5. 如有需要，可导出扫描报告或日志内容。

## 免责声明
本工具仅用于授权的安全测试和教育目的。  
未经授权扫描他人系统是违法行为，请严格遵守相关法律法规。  
使用本工具造成的一切后果由使用者自行承担。

## 许可证
本项目基于 **MIT License** 发布，详情见 `LICENSE` 文件。

## 版本历史
- v1.0.0：初始版本发布
