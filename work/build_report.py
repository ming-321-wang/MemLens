# -*- coding: utf-8 -*-
"""MemLens 解 2025 平航杯【免费工具版】取证题 · 详细工具解题教程（python-docx）。
用法：python build_report.py  → 生成 memlens_pinghang_tutorial.docx
"""
import os, sys
from docx import Document
from docx.shared import Pt, Cm, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

BASE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(BASE, 'MemLens解平航杯取证题教程.docx')
SONG, HEI, TIMES, MONO = '宋体', '黑体', 'Times New Roman', 'Consolas'


def set_font(run, ascii_font=TIMES, east_font=SONG, size=12, bold=False, color=None):
    run.font.name = ascii_font
    run.font.size = Pt(size)
    run.font.bold = bold
    if color:
        run.font.color.rgb = color
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn('w:rFonts'))
    if rfonts is None:
        rfonts = OxmlElement('w:rFonts'); rpr.append(rfonts)
    rfonts.set(qn('w:ascii'), ascii_font); rfonts.set(qn('w:hAnsi'), ascii_font)
    rfonts.set(qn('w:eastAsia'), east_font)


def no_borders(t):
    tbl = t._tbl
    for cell in tbl.iter_tcs():
        tcPr = cell.get_or_add_tcPr()
        borders = OxmlElement('w:tcBorders')
        for edge in ('top', 'left', 'bottom', 'right'):
            el = OxmlElement('w:' + edge); el.set(qn('w:val'), 'nil')
            borders.append(el)
        tcPr.append(borders)


def shade(paragraph, fill='F2F4F7'):
    ppr = paragraph._p.get_or_add_pPr()
    shd = OxmlElement('w:shd'); shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto'); shd.set(qn('w:fill'), fill)
    ppr.append(shd)


def heading(doc, text, level=1):
    size = {1: 16, 2: 14, 3: 12.5}[level]
    p = doc.add_paragraph()
    p.style = doc.styles['Heading %d' % level]
    pf = p.paragraph_format
    pf.space_before = Pt(14 if level == 1 else 10)
    pf.space_after = Pt(8 if level == 1 else 5)
    pf.keep_with_next = True
    r = p.add_run(text)
    set_font(r, TIMES, HEI, size, bold=True,
             color=RGBColor(0x1F, 0x3B, 0x63) if level == 1 else None)
    return p


def body(doc, text, size=12, indent=True):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    pf = p.paragraph_format
    pf.space_after = Pt(6); pf.line_spacing = 1.5
    if indent:
        pf.first_line_indent = Pt(size * 2)
    set_font(p.add_run(text), TIMES, SONG, size)
    return p


def bullet(doc, text, size=12):
    p = doc.add_paragraph(style='List Bullet')
    pf = p.paragraph_format
    pf.space_after = Pt(3); pf.line_spacing = 1.4
    set_font(p.add_run(text), TIMES, SONG, size)
    return p


def code(doc, text):
    for line in text.split('\n'):
        p = doc.add_paragraph()
        pf = p.paragraph_format
        pf.space_after = Pt(0); pf.line_spacing = 1.15
        pf.left_indent = Cm(0.4)
        shade(p)
        set_font(p.add_run(line if line else ' '), MONO, MONO, 9.5)
    doc.add_paragraph().paragraph_format.space_after = Pt(2)


def table(doc, header, rows, widths=None, size=10.5):
    t = doc.add_table(rows=0, cols=len(header))
    t.style = 'Table Grid'
    h = t.add_row().cells
    for i, x in enumerate(header):
        p = h[i].paragraphs[0]; p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        set_font(p.add_run(x), TIMES, HEI, size, bold=True)
        tcpr = h[i]._tc.get_or_add_tcPr()
        shd = OxmlElement('w:shd'); shd.set(qn('w:val'), 'clear')
        shd.set(qn('w:fill'), 'E8EDF4'); tcpr.append(shd)
    for row in rows:
        cells = t.add_row().cells
        for i, val in enumerate(row):
            cells[i].text = ''
            p = cells[i].paragraphs[0]
            p.paragraph_format.space_after = Pt(2)
            set_font(p.add_run(str(val)), TIMES, SONG, size)
    if widths:
        for i, w in enumerate(widths):
            t.columns[i].width = Cm(w)
            for row in t.rows:
                row.cells[i].width = Cm(w)
    doc.add_paragraph()
    return t


def add_page_number(sec):
    p = sec.footer.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(p.add_run('第 '), TIMES, SONG, 10)
    fld = OxmlElement('w:fldSimple'); fld.set(qn('w:instr'), 'PAGE')
    p._p.append(fld)
    set_font(p.add_run(' 页'), TIMES, SONG, 10)


def build():
    doc = Document()
    sec = doc.sections[0]
    sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
    sec.left_margin = sec.right_margin = Cm(2.6)
    sec.top_margin, sec.bottom_margin = Cm(2.5), Cm(2.3)
    add_page_number(sec)
    doc.styles['Normal'].font.name = TIMES
    doc.styles['Normal'].element.rPr.rFonts.set(qn('w:eastAsia'), SONG)

    # ── 封面 ──
    for _ in range(4):
        doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(p.add_run('MemLens 解 2025 平航杯【免费工具版】取证题'), TIMES, HEI, 24, bold=True,
             color=RGBColor(0x1F, 0x3B, 0x63))
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(p.add_run('详 细 工 具 解 题 教 程'), TIMES, HEI, 18, bold=True)
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_font(p.add_run('命令行 + 可视化双入口 · MemLens v14'), TIMES, SONG, 12)
    for _ in range(2):
        doc.add_paragraph()
    t = doc.add_table(rows=0, cols=2); no_borders(t)
    for k, v in [('工 具 名 称', 'MemLens 内存/磁盘取证工作台'),
                 ('版        本', 'v14（含 URL/境外IP/浏览器/服务器文件级取证）'),
                 ('解 题 范 围', '0x00 前言 · 0x01 计算机取证 · 0x05 服务器取证'),
                 ('适 用 对 象', '不熟命令行的使用者（可视化）与取证工程师（命令行）'),
                 ('授 权 前 提', 'CTF 赛题 / 自建靶场 / 有书面授权的取证演练')]:
        cells = t.add_row().cells
        cells[0].width, cells[1].width = Cm(4.2), Cm(11.0)
        p0 = cells[0].paragraphs[0]; p0.alignment = WD_ALIGN_PARAGRAPH.CENTER
        set_font(p0.add_run(k), TIMES, SONG, 11)
        p1 = cells[1].paragraphs[0]
        set_font(p1.add_run(v), TIMES, SONG, 11)
    doc.add_page_break()

    # ── 一、教程目的 ──
    heading(doc, '一、教程目的', 1)
    body(doc, '本教程教你用 MemLens（已内置平航杯 2025【免费工具版】取证题的解题能力）'
              '从题目附件一路解到答案。全程两条路：可视化（浏览器页面点按钮，适合不熟命令行）'
              '与命令行（一条命令一个结论，适合取证工程师）。'
              '学完本教程，0x00 载体判断、0x01 计算机取证的浏览器/注册表/事件日志、'
              '0x05 服务器取证的 URL/境外 IP/网站日志/一句话木马/密码加密/开机时间/用户数/订单数，'
              '都可以用 MemLens 直接解出，不需要手动挂载系统跑命令。')

    # ── 二、环境与工具 ──
    heading(doc, '二、环境与工具', 1)
    table(doc, ['项目', '值', '说明'],
          [['MemLens', 'v14（exe）', 'D:\\MemLens\\dist\\MemLens\\MemLens.exe（桌面快捷方式同款）'],
           ['可视化入口', 'http://127.0.0.1:8765', '双击 exe 自动打开；「浏览器」标签页有 3 个取证卡片'],
           ['命令行入口', 'MemLens.exe <子命令>', 'url-analyze / web-log / browser-history / server / container'],
           ['题目附件', '平航杯题目（70 GiB 无扩展名）', '先判断载体（0x00）再决定用什么工具'],
           ['服务器检材', 'export-disk0-000002.vmdk', '0x05 服务器取证的磁盘镜像'],
           ['结果目录', 'work\\（exe 同级）', '--json / --report 导出到这里']],
          widths=[2.8, 5.2, 8.0], size=10)

    # ── 三、原理 ──
    heading(doc, '三、原理（MemLens 怎么解）', 1)
    heading(doc, '3.1 载体判断与容器挂载', 2)
    body(doc, '题目附件是无扩展名大文件，不能默认它是磁盘/压缩/内存镜像。MemLens「取证容器」通道'
              '先按大小、文件头、文件尾判断载体类型（容器文件/虚拟磁盘/加密卷），再决定 VeraCrypt 挂载、'
              'EWF(E01) 转 vmdk、XFS/LVM 分析，全程不依赖手动挂载。')
    heading(doc, '3.2 境外 IP / URL 识别与风险分级', 2)
    body(doc, 'url_analyze 把 URL 解析成 域名/端口/路径，再对 IP 做归属识别：命中内置中国网段'
              '（教育网+常见国内段+国内云段）判「境内」，未命中的公有 IP 判「境外（疑似）」，'
              '私有/保留判「内网」。风险分级：境外 IP 直连 / .onion / 境外+可疑 TLD → 高；'
              '非 HTTPS / 可疑免费 TLD / 风险关键词 → 中；境内 HTTPS 正常 → 低。'
              '可用 --ip-map（域名=IP，从 pcap/流量提取）精确化，或 --resolve 联网 DNS。')
    heading(doc, '3.3 服务器文件级分析（不挂载系统）', 2)
    body(doc, '0x05 服务器取证的多数题只需读文件，不用启动虚拟机：wtmp（开机时间）、'
              '/etc/passwd（用户数）、trojan config.json（域名/模式/端口）、config.php（AUTH_CODE 加密）、'
              'SQL 导出（订单数/用户间隔）。MemLens 的 server 子命令直接解析这些文件。')

    # ── 四、解题步骤 ──
    heading(doc, '四、解题步骤（逐题，命令 + 可视化）', 1)

    heading(doc, '4.0 第 0 步 · 打开镜像 / 判断载体（0x00）', 2)
    body(doc, '双击 MemLens → 打开证据文件 → 选「平航杯题目」→ 容器通道识别载体。')
    code(doc, 'MemLens.exe container 平航杯题目 identify      # 判断载体类型\n'
              'MemLens.exe container 平航杯题目 crypto       # VeraCrypt 卷头详情\n'
              'MemLens.exe container 平航杯题目 files        # 挂载并列出卷内文件')
    body(doc, '可视化：打开页面 → 「工具」→「取证容器」→ 选镜像 → 识别/列文件。')

    heading(doc, '4.1 浏览器历史 · 默认浏览器 / 小说（0x01 题 3/4）', 2)
    body(doc, '题 3 默认浏览器、题 4 浏览器看过的小说，都在浏览器历史里。MemLens 检测本机或镜像里的'
              '所有浏览器（Edge/Chrome/Firefox/Brave/Vivaldi/Opera/搜狗…）。')
    code(doc, 'MemLens.exe browser-history --appdata "E:\\镜像\\Users\\起早王\\AppData" --risk --report work\\浏览器报告.md\n'
              'MemLens.exe browser-history --all-drives --risk     # 本机全盘扫描')
    body(doc, '可视化：「浏览器」标签 → 填 AppData（镜像提取的 Users\\<用户>\\AppData，留空=本机）'
              '→ 勾全盘 → 点「扫描 + 境外IP风险」。')

    heading(doc, '4.2 境外 IP / URL 分析（0x01 浏览器 + 0x05 URL）', 2)
    body(doc, '浏览器报告会单独列出「境外（疑似）地址访问」并标风险等级；也可直接分析任意 URL。')
    code(doc, 'MemLens.exe url-analyze "https://8.8.8.8/admin" "http://abc.xyz/pay" --ip-map 域名IP.txt\n'
              'MemLens.exe url-analyze "http://192.168.100.1:8098"    # 内网识别')
    body(doc, '可视化：同「浏览器」标签 → 境外 IP / 风险摘要表（高/中/低 + 境外条数）。')

    heading(doc, '4.3 服务器文件级取证（0x05 题 1/3/4/5/7/9）', 2)
    body(doc, '从 vmdk 提取文件（container xfs/extract）后直接喂给 server 子命令，不用挂载系统。')
    code(doc, 'MemLens.exe server wtmp    <镜像>\\var\\log\\wtmp          # 题1 最早开机时间\n'
              'MemLens.exe server passwd  <镜像>\\etc\\passwd             # 题3 用户数\n'
              'MemLens.exe server trojan  <镜像>\\root\\trojan\\config.json # 题4/5/6 域名/模式/端口\n'
              'MemLens.exe server php     <镜像>\\application\\config.php --password sbwyz1  # 题7 密码md5\n'
              'MemLens.exe server sql     <镜像>\\www\\wwwroot\\dump.sql    # 题9 订单数 / 题14 最短间隔')
    body(doc, '可视化：「浏览器」标签 →「服务器文件级取证」卡片 → 选类型 + 填路径 →「分析」。')

    heading(doc, '4.4 网站日志 / 一句话木马（0x05 题 11/12）', 2)
    body(doc, 'access.log 分析出攻击者 IP、可疑探测、上传、一句话木马 SHA-256。')
    code(doc, 'MemLens.exe web-log <镜像>\\www\\wwwlogs\\access.log --json   # → work\\web_log.json')
    body(doc, '可视化：「网站日志 / 扫描器」卡片 → 填 access.log 路径或粘贴 →「日志分析」。')

    heading(doc, '4.5 扫描器 result.txt（0x05 题 13 / 内网 URL）', 2)
    body(doc, '解析扫描器输出的 [url]/[title]/[finger]/[icmp] 块 → URL+端口+title+指纹+内网/境外。')
    code(doc, 'MemLens.exe url-analyze --scanner <镜像>\\application\\result.txt --json')
    body(doc, '可视化：「网站日志 / 扫描器」卡片 →「扫描器解析」。')

    # ── 五、问题与解决 ──
    heading(doc, '五、问题与解决', 1)
    table(doc, ['#', '现象', '根因', '解决'],
          [['1', '命令行没输出', 'windowed exe 无控制台（console=False）', '结果用 --json/--report 导出 work\\；或看 work\\memlens.log'],
           ['2', '首行不识别/中文乱码', '日志文件带 BOM（Out-File utf8）', '已兼容 utf-8-sig + lstrip(\\ufeff)，直接重跑即可'],
           ['3', 'CLI 子命令不生效', 'main.py 不转发 CLI（历史 bug）', 'v10 起已修复：MemLens.exe url-analyze … 直接走 CLI'],
           ['4', '找不到镜像内文件', '文件在 vmdk 里未提取', '先 MemLens.exe container <镜像> xfs 提取，再喂 server/web-log'],
           ['5', '时间差 8 小时', 'wtmp 存 UTC，last 显示本地', 'server wtmp 用本地时区显示，与 last 一致'],
           ['6', '境外误报', '内置网段保守，国内云/CDN 可能误标', '用 --ip-map（pcap 域名=IP）精确；"疑似"措辞']],
          widths=[0.8, 4.2, 4.8, 6.2], size=9.5)

    # ── 六、结论 ──
    heading(doc, '六、结论', 1)
    bullet(doc, '能解：0x00 载体判断/Hash/VeraCrypt/E01；0x01 浏览器历史/默认浏览器/小说；'
                '0x05 开机时间/用户数/Trojan 域名与模式/密码 md5/订单数/攻击者 IP/一句话木马 SHA-256/'
                'rdp 账号/内网 URL/扫描器输出。')
    bullet(doc, '可视化 + 命令行双入口，不熟命令行者用浏览器页面点按钮即可。')
    bullet(doc, '剩余需专门工具/挂载系统：0x02 Neo4j 图、0x03 AES(Java)、0x04 PE 逆向、'
                '0x06/0x07 BLE/USB 抓包解析、GD 版本（需 php 运行）。')

    # ── 附录 A 命令速查 ──
    heading(doc, '附录 A  命令速查', 1)
    code(doc, 'MemLens.exe container <镜像> identify            # 载体判断\n'
              'MemLens.exe container <镜像> crypto              # VeraCrypt 卷头\n'
              'MemLens.exe container <镜像> xfs                 # 磁盘 XFS 分析\n'
              'MemLens.exe browser-history --appdata <AppData> --risk --report work\\报告.md\n'
              'MemLens.exe url-analyze <url...> --ip-map 域名IP.txt\n'
              'MemLens.exe url-analyze --scanner <result.txt> --json\n'
              'MemLens.exe web-log <access.log> --json\n'
              'MemLens.exe server wtmp|passwd|trojan|php|sql <文件> [--password 明文] [--json]')

    # ── 附录 B 平航杯答案对照 ──
    heading(doc, '附录 B  平航杯 2025【免费工具版】答案对照（WP 标准答案）', 1)
    table(doc, ['题号', '答案', 'MemLens 途径'],
          [['0x00-1 载体', '70GiB 容器文件（VeraCrypt）', 'container identify'],
           ['0x01-3 默认浏览器', 'Firefox', 'browser-history（注册表 UserChoice）'],
           ['0x01-4 看的小说', '十日终焉（历史记录）', 'browser-history'],
           ['0x05-1 最早开机', '2022/2/23 12:23:49', 'server wtmp'],
           ['0x05-2 内核', '3.10.0-1160.119.1.el7.x86_64', '（提取 /etc/redhat-release 或 uname）'],
           ['0x05-3 用户数', '3（root/www/mysql）', 'server passwd'],
           ['0x05-4 Trojan 域名', 'wyzshop1.com', 'server trojan'],
           ['0x05-5 模式', 'nat', 'server trojan（对照 examples）'],
           ['0x05-6 remote 作用', 'A 转发外部互联网服务器', 'server trojan'],
           ['0x05-7 密码 md5', 'f8537858eb0eabada34e7021d19974ea', 'server php --password sbwyz1'],
           ['0x05-8 GD 版本', 'bundled (2.1.0 compatible)', '（需 php -r gd_info，挂载系统）'],
           ['0x05-9 订单数', '1292', 'server sql'],
           ['0x05-11 攻击者 IP', '222.2.2.2', 'web-log'],
           ['0x05-12 木马 sha256', '870BF66B…CBC7CF', 'web-log（一句话木马）'],
           ['0x05-13 rdp 账号', 'administrator:Aa123456@', 'url-analyze --scanner（result.txt）'],
           ['0x05-14 最短用户', '（用户 id）', 'server sql']],
          widths=[2.6, 6.4, 7.0], size=9.5)

    doc.save(OUT)
    print('saved:', OUT)


if __name__ == '__main__':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    build()
