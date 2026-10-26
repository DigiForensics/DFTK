"""Shared bilingual discovery vocabulary; no zero-token alphabetic fallback."""
QUERY_ALIASES = {
    '通讯录': 'contacts android mobile sqlite', '联系人': 'contacts android mobile sqlite',
    '短信': 'sms message android mobile sqlite', '聊天': 'message chat sqlite',
    '通话': 'call android mobile sqlite', '域名': 'domain url endpoint network',
    '网址': 'url endpoint network', '服务器': 'server endpoint linux network',
    '登录': 'login auth authentication', '数据库': 'database sqlite sql',
    '流量': 'pcap network dns http tls', '注册表': 'registry windows',
    '浏览器': 'browser chromium firefox', '时间': 'time timestamp timeline',
    '哈希': 'hash sha256 artifact', '邮件': 'email mime dkim spf',
    '图片': 'media image metadata ocr', '照片': 'media image metadata exif',
    '截图': 'media image ocr', '视频': 'media video preview',
    '文字识别': 'media ocr text', '加密': 'encrypted archive crypto',
    '解密': 'crypto decrypt encrypted', '裁剪': 'media image crop',
    '批量识别': 'media ocr batch', '批量看图': 'media image contact sheet preview',
    '密码': 'password archive', '压缩包': 'archive encrypted',
    '文件内容': 'file read text', '目录': 'evidence browse directory',
    '持久化': 'persistence linux windows', '外传': 'network http sessions upload',
    '删除': 'deleted recover sqlite filesystem',
}


def expand_query(query: str) -> str:
    return ' '.join([query] + [replacement for key, replacement in QUERY_ALIASES.items() if key in query])
