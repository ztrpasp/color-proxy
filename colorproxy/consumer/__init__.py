"""消费端（请求端 Consumer）：浏览器侧 HTTP 正向代理。

截取浏览器 HTTP 请求，经共生网络（CoLoR）"先拉后推"握手送达提供端取回响应。
与服务端共享 ``colorproxy.protocol`` / ``colorproxy.transport`` 与注册逻辑，
仅新增 HTTP 正向代理、SID 表（从 RM 拉取）与握手编排。
"""
