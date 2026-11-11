nid:
6566dbbdb1946c83bb35764552c68a2a
sid:
a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a247b1fbcd9815c47058819aa19b53dc69d919eba8


acl add id 5 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a282bae96c055a0e5763365aa75422fcf61fe8cb66 asid 0x00000001 nid 6566dbbdb1946c83bb35764552c68a2a


acl add id 5 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a282bae96c055a0e5763365aa75422fcf61fe8cb66 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2

---

# L3 测试用 ACL 规则（2026-10-25 生成）

- 消费端：nid `b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2`（config-consumer.json），在 AS1 → `asid 0x00000001`
- 规则全部是 `deny`。RM 按 id 从小到大找第一条命中的规则，都没命中就放行；id 不能重复，重复会报 `maybe duplicated id`
- 想对任意消费端生效，把 nid 写成 `00000000000000000000000000000000`（全 0 是通配）
- 加完用 `display acl` 看，删除用 `acl delete id <id>`
- 服务级 SID 只拦**新连接**：消费端每条新 TCP 连接 / 新 UDP 流都会先发一次 GET（D19），已经建好的连接不受影响
- 8000 上的 URL SID 是逐请求的（D20）：拦了某个 URL，只有那个请求被 RST，同站其它页面照常；URL 的 query 不参与 SID

## 提供端 A：AS2（172.10.9.2）

提供端 NID `a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`（仓库 config.json 的 nid）

### 服务级（id 101–104）

| id | 服务 | 拦掉后的效果 |
|---|---|---|
| 101 | `tcp://172.10.9.2:8000` | 整个 8000 站点的新连接都建不起来 |
| 102 | `tcp://172.10.9.2:21` | FTP 新会话连不上（被动数据连接跟着控制 SID 走，不用另拦） |
| 103 | `tcp://172.10.9.2:3306` | MySQL 新连接建不起来 |
| 104 | `udp://172.10.9.2:5004` | RTP 新的 UDP 流（四元组空闲 60 s 才算新流） |

```
acl add id 101 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a195f63dd34c49deacfaa001a128e508eff50ab7b7 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 102 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1c5081681b1ec98e3c025a751a66cd6bb46055235 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 103 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a158af97df996faff83beac5cd57ed59e7f4b4b736 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 104 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a12a3e161484aa1c34325188894cfb2df576a8a811 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
```

### 内容级：8000 上的 26 个 URL（id 111–136）

| id | URL |
|---|---|
| 111 | `http://172.10.9.2:8000/` |
| 112 | `http://172.10.9.2:8000/hello.html` |
| 113 | `http://172.10.9.2:8000/favicon.ico` |
| 114 | `http://172.10.9.2:8000/showcase.html` |
| 115 | `http://172.10.9.2:8000/items.html` |
| 116 | `http://172.10.9.2:8000/monitor.html` |
| 117 | `http://172.10.9.2:8000/realtimemonitor.html` |
| 118 | `http://172.10.9.2:8000/model.html` |
| 119 | `http://172.10.9.2:8000/ping` |
| 120 | `http://172.10.9.2:8000/slow` |
| 121 | `http://172.10.9.2:8000/api/items` |
| 122 | `http://172.10.9.2:8000/api/monitor/recent` |
| 123 | `http://172.10.9.2:8000/api/monitor/snapshot` |
| 124 | `http://172.10.9.2:8000/api/monitor/stream` |
| 125 | `http://172.10.9.2:8000/api/monitor/location-a/recent` |
| 126 | `http://172.10.9.2:8000/api/monitor/location-a/snapshot` |
| 127 | `http://172.10.9.2:8000/api/monitor/location-a/stream` |
| 128 | `http://172.10.9.2:8000/api/monitor/location-b/recent` |
| 129 | `http://172.10.9.2:8000/api/monitor/location-b/snapshot` |
| 130 | `http://172.10.9.2:8000/api/monitor/location-b/stream` |
| 131 | `http://172.10.9.2:8000/api/models` |
| 132 | `http://172.10.9.2:8000/api/model/questions` |
| 133 | `http://172.10.9.2:8000/api/model/medical` |
| 134 | `http://172.10.9.2:8000/api/model/medical/stream` |
| 135 | `http://172.10.9.2:8000/api/model/education` |
| 136 | `http://172.10.9.2:8000/api/model/education/stream` |

```
acl add id 111 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a17b24a8ee340631503ec3ac97b6b8da849a4b7f1f asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 112 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a15fd0da4e0205e35fd4383ecd37f3e5536dfb4410 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 113 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a11b6486bec4ff0f5721c9b1c7146e5b0bf1b48b64 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 114 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a145ced527f620d9913fb35af617340dbb15b57201 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 115 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b10d7d7df3b8ae0172d035abff93c44f76b76d68 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 116 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a119c4b5373beb8f90ac1495205b74e1092e73e556 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 117 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a140fca561308b4d0222add400b7585ea6a8a2763b asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 118 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a14340bdfde96cc91f3adc25954df113474f924882 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 119 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b852935980d962a8148a24b7cf65ec3c4fcdb746 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 120 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a16bbdd4ecdbe83d4e01270451ba25d8f065e17501 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 121 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1102dd70245493cfb946cfe35d40df1519d178dee asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 122 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1dc9ae45b734537b78df338740a1e51a0f94caf45 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 123 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10b4dae1358bbad318ac942ded9d8ca76643a80c5 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 124 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a15db813d876062480b0e8d6b3d01d76e41da43d54 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 125 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10ca1957534289889bc786170249ae9f5851ea3e0 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 126 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1b84b91b8f91dc0da53ef994ca760d75c8ac7942e asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 127 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a129c8d61ae23c3bd6c586fbac076898c6abc91064 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 128 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a16d76bdf4deb38d0634418f88eeaaf9067374cb2e asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 129 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a14745c2c37c1df8bdbc51a425e3d12ab1d50d833f asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 130 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a13044a687e782764e3504aa7d21f70d07104bda38 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 131 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a115a1f96bd8e28a1d425765eedf0e684f4ed955cf asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 132 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1d9753c57ad8af1d49a220439fe5ca8d9abc7a49e asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 133 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a18675f4a0296de4366d1ce829a8897d0f6f46fe21 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 134 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a158d8bc04f2d609f2930b3632acf8ff8604ee1b49 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 135 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a170354d99782a30bf69ab09657467c77c3b79bc59 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 136 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1020d895d2b03bd9a65c9856f12c90fb157885125 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
```

### 删除本节全部规则

```
acl delete id 101
acl delete id 102
acl delete id 103
acl delete id 104
acl delete id 111
acl delete id 112
acl delete id 113
acl delete id 114
acl delete id 115
acl delete id 116
acl delete id 117
acl delete id 118
acl delete id 119
acl delete id 120
acl delete id 121
acl delete id 122
acl delete id 123
acl delete id 124
acl delete id 125
acl delete id 126
acl delete id 127
acl delete id 128
acl delete id 129
acl delete id 130
acl delete id 131
acl delete id 132
acl delete id 133
acl delete id 134
acl delete id 135
acl delete id 136
```

## 提供端 B：AS4（172.20.9.2）

提供端 NID `a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1`（与 AS2 提供端相同）

### 服务级（id 201–204）

| id | 服务 | 拦掉后的效果 |
|---|---|---|
| 201 | `tcp://172.20.9.2:8000` | 整个 8000 站点的新连接都建不起来 |
| 202 | `tcp://172.20.9.2:21` | FTP 新会话连不上（被动数据连接跟着控制 SID 走，不用另拦） |
| 203 | `tcp://172.20.9.2:3306` | MySQL 新连接建不起来 |
| 204 | `udp://172.20.9.2:5004` | RTP 新的 UDP 流（四元组空闲 60 s 才算新流） |

```
acl add id 201 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a19368f5835317101ab532b838c16c66588d74acc0 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 202 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a16a924a3b864fa9ab7755489ac2d4efb329811a7e asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 203 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a117395aaf1877feaa848a66cb4c09b5ec78956a82 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 204 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a18345f07f00e7e8acdbdee5350262c69c636b84ec asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
```

### 内容级：8000 上的 26 个 URL（id 211–236）

| id | URL |
|---|---|
| 211 | `http://172.20.9.2:8000/` |
| 212 | `http://172.20.9.2:8000/hello.html` |
| 213 | `http://172.20.9.2:8000/favicon.ico` |
| 214 | `http://172.20.9.2:8000/showcase.html` |
| 215 | `http://172.20.9.2:8000/items.html` |
| 216 | `http://172.20.9.2:8000/monitor.html` |
| 217 | `http://172.20.9.2:8000/realtimemonitor.html` |
| 218 | `http://172.20.9.2:8000/model.html` |
| 219 | `http://172.20.9.2:8000/ping` |
| 220 | `http://172.20.9.2:8000/slow` |
| 221 | `http://172.20.9.2:8000/api/items` |
| 222 | `http://172.20.9.2:8000/api/monitor/recent` |
| 223 | `http://172.20.9.2:8000/api/monitor/snapshot` |
| 224 | `http://172.20.9.2:8000/api/monitor/stream` |
| 225 | `http://172.20.9.2:8000/api/monitor/location-a/recent` |
| 226 | `http://172.20.9.2:8000/api/monitor/location-a/snapshot` |
| 227 | `http://172.20.9.2:8000/api/monitor/location-a/stream` |
| 228 | `http://172.20.9.2:8000/api/monitor/location-b/recent` |
| 229 | `http://172.20.9.2:8000/api/monitor/location-b/snapshot` |
| 230 | `http://172.20.9.2:8000/api/monitor/location-b/stream` |
| 231 | `http://172.20.9.2:8000/api/models` |
| 232 | `http://172.20.9.2:8000/api/model/questions` |
| 233 | `http://172.20.9.2:8000/api/model/medical` |
| 234 | `http://172.20.9.2:8000/api/model/medical/stream` |
| 235 | `http://172.20.9.2:8000/api/model/education` |
| 236 | `http://172.20.9.2:8000/api/model/education/stream` |

```
acl add id 211 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a165c79d702e126de4e834151f011706bceef33f0d asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 212 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a15883dc3de5a0098b9e56ca7e49576fe52d85456a asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 213 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a11747189d3b94dc5d40fe5e92913ff0e468198aef asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 214 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a179b9f6d9df0fb0c5f288ff91c56135d5ec324ec3 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 215 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1e46bd8536487bc8fbb7e323d72226fba51a1f1d2 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 216 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1747858eccb53b69ed155e1a191ab02be7e28e263 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 217 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ef36c169ac82532c75e3525a73b7771bb6c3fa87 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 218 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1312cb55c3eb523f25ea5bb7e65a863d76fd2c84d asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 219 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1f77edc80774e65d3a99a6844dcec9158ef1a1f13 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 220 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1d97dabe89d1a59eaef0f5b70b8417660c08a5f71 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 221 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1dc1439d2e60d926bff2f49dd2fa01cdfec7f340c asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 222 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a167f00ca2075a42096199310f16f677ffdc9492d2 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 223 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1ea3f5b8b50127de4c17e0e6f2679550c209f6419 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 224 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a19d4063159b5c81d383786608e236234b72437c01 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 225 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1412ef3352485d5b318e09d3fd9303d671bb8f34f asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 226 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a169fe0ebd9391808f81d861b9bfc086a336e87bd1 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 227 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a157dbdd913fc7f10290835299e7b572b8b65567ad asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 228 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1c7f345d2f8ea192c46eae6993110294c0fc62364 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 229 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1fe4dfd271799030e6698ea7db12e5bd747dbc346 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 230 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a18641ecc2faa801d9d1e68c0fd97a6a1853f2b295 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 231 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a186cd3bae93572501bbf3da8c8a55d7293dc2da76 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 232 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10422b1c297e17e9c189c47ca4ab26a9af6f42362 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 233 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a19fcca16d1ca923ecdecb5d74edc4588bb6403bf6 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 234 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1d03c5fb224ee2cfee5ca3cb568d1162018c04154 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 235 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a127d055da5eefbc5a1ab8edf8d8d627f74d60564f asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
acl add id 236 action deny sid a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a101213c0a5147f4519d82fac5d1cd9f11e55b5f27 asid 0x00000001 nid b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2
```

### 删除本节全部规则

```
acl delete id 201
acl delete id 202
acl delete id 203
acl delete id 204
acl delete id 211
acl delete id 212
acl delete id 213
acl delete id 214
acl delete id 215
acl delete id 216
acl delete id 217
acl delete id 218
acl delete id 219
acl delete id 220
acl delete id 221
acl delete id 222
acl delete id 223
acl delete id 224
acl delete id 225
acl delete id 226
acl delete id 227
acl delete id 228
acl delete id 229
acl delete id 230
acl delete id 231
acl delete id 232
acl delete id 233
acl delete id 234
acl delete id 235
acl delete id 236
```
