# Windows 注册表取证中的名称与路径归属歧义分析

**分析对象**：python-registry（本仓库 `Registry/RegistryParse.py`、`Registry/Registry.py`）
**方法**：本地构造 5 个合成 Hive 样本（`analysis/name_ambiguity/hives/`），沿"底层记录 → 名称解码 → 路径拼接 → 键/值查找 → 展示输出"五层逐层比对，定位证据被归到错误键的输入类别。
**复现方式**：

```bash
python3 analysis/name_ambiguity/build_samples.py     # 生成样本 hive
python3 analysis/name_ambiguity/analyze_samples.py   # 主分析（输出见 analysis_output.txt）
python3 analysis/name_ambiguity/probe_extra.py       # 补充探针（输出见 probe_extra_output.txt）
```

样本 hive 由 `analysis/name_ambiguity/hivebuilder.py` 按 REGF/HBIN/NK/VK/LF 结构手工构造，校验和有效（`validate_checksum() == True`），即解析器把它们当作完全合法的 hive 接受——所有差异都来自名称语义层，而非文件损坏。

---

## 1. 名称处理链路现状

| 层 | 代码位置 | 行为 |
|---|---|---|
| 原始记录 | NKRecord `RegistryParse.py:1530-1542`、VKRecord `RegistryParse.py:964-987` | 按标志位选择解码：NK 用 `flags & 0x20`（COMP_NAME），VK 用 `flags & 0x01`；置位→`windows-1252`，否则→`utf-16le` |
| 值数据解码 | `decode_utf16le()` `RegistryParse.py:778-809` | 用 `b"\x00\x00"` 启发式找结尾，再 `partition('\x00')[0]` 截断 |
| 路径拼接 | `NKRecord.path()` `RegistryParse.py:1544-1560` | 沿父链取 `name()`，用 `'\\'` 连接 |
| 键查找 | `RegistryKey.subkey()` `Registry.py:314-326`、`find_key()` `Registry.py:356-364` | 线性扫描，`k.name().lower() == name.lower()`，**首个匹配即返回**；`find_key` 按 `'\\'` 分段 |
| 值查找 | `RegistryKey.value()` `Registry.py:340-354` | 同样 `.lower()` 首个匹配；且 `name == "(default)"` 被硬编码改写为空名 |
| 展示 | `RegistryValue.name()` `Registry.py:113-121`、`__str__/__repr__` | 无名值显示为 `"(default)"`，与字面值名 `"(default)"` 不可区分 |

关键事实：**名称解码后，原始字节与标志位即被丢弃**，下游（路径、查找、展示）全部工作在解码后的 `str` 上。这是所有归属歧义的结构性根源。

---

## 2. 实证发现

### F1 压缩名称（COMP_NAME）标志被盲信 —— 标志与内容不匹配时身份完全错乱

样本：`compressed_names.hive`

| 子键 | 原始字节 | 标志 | `name()` 结果 | 后果 |
|---|---|---|---|---|
| `PlainASCII` | `b'PlainASCII'` | 压缩 | `'PlainASCII'` | 正常 |
| `Ünïcode` | `b'\xdcn\xefcode'` | 压缩 | `'Ünïcode'` | 正常（高 Latin-1 字符压缩存储合法） |
| `CJK键` | UTF-16LE | 未压缩 | `'CJK键'` | 正常 |
| **FlagLie** | UTF-16LE 的 `"FlagLie"` | **错置压缩位** | `'F\x00l\x00a\x00g\x00L\x00i\x00e\x00'` | 名称内嵌 7 个 NUL；`subkey("FlagLie")` 永不命中；C 风格截断的查看器显示为 `"F"` |
| **RawBytes** | Latin-1 的 `"RawBytes"` | **错清压缩位** | `'\u6152\u4277\u7479\u7365'`（4 个 CJK 字符） | 键身份彻底丢失，被归到一个完全不存在的"中文名"键 |
| **OddLen** | 奇数长度 UTF-16 | 未压缩 | 抛 `UnicodeDecodeError: truncated data` | 该键对 `name()`/`path()`/查找**整体不可达** |

结论：解析器无条件信任标志位（`RegistryParse.py:1530-1531`、`970-974`），不做任何交叉校验（如"压缩字节串是否含 `0x00`"、"UTF-16 长度是否为偶数"）。标志位被篡改、损坏或写入方实现错误时，**证据会被归到错误名称的键，且无任何告警**。

### F2 UTF-16 代理项 —— 合法代理对可用，孤立代理项毒化整个父分支

样本：`surrogate_names.hive`

- 合法代理对 `Emoji\U0001F600Key`：`name()`、`path()`、UTF-8/JSON 输出全部正常。
- 孤立高/低代理项、反向代理对（均可用原始 hive 构造，WinAPI 不会写出）：`name()` 直接抛 `UnicodeDecodeError`（`illegal UTF-16 surrogate` / `illegal encoding`）。
- **连带拒绝**（`probe_extra.py` A 组）：`subkey()` 在比较时会先对列表中每个键调用 `k.name()`（`Registry.py:324`），于是一个孤立代理项的"毒键"导致：
  - 对**不存在的键**的查询抛 `UnicodeDecodeError` 而非 `RegistryKeyNotFoundException`——异常类型改变，依赖异常类型做兼容处理的调用方逻辑失效；
  - `[k.name() for k in root.subkeys()]` 整体崩溃——**同一父键下所有正常兄弟键的名称都无法枚举**，只有排在毒键之前（lf 列表序）的键能被按名查到。

### F3 大小写等价重复名 —— "列表序第一者胜"，证据静默归错

样本：`case_collision.hive`（`Evidence` / `EVIDENCE` / `evidence` 三个仅大小写不同的子键，各带区分性 `Marker` 值）

实测（`analysis_output.txt` HIVE 3）：

```
open('Evidence') -> marker='first-in-list'
open('EVIDENCE') -> marker='first-in-list'
open('evidence') -> marker='first-in-list'
open('eViDeNcE') -> marker='first-in-list'
```

四个查询全部解析到 lf 列表中的**第一个**键；`EVIDENCE`（`second-in-list`）与 `evidence`（`third-in-list-utf16`）两个键**按名永远不可达**，只能枚举发现。值层面同样：`DupValues` 键中 `Data`/`DATA` 两个值，`value('DATA')` 返回的是 `value-lower-first`。

虽然 WinAPI 不允许活动键重名，但以下情形在真实取证中会出现此类碰撞：被删除键与活动键共存于 hive 空闲/残留单元、手工构造的对抗性 hive、以及 carved 记录。此时 `subkey()`/`find_key()` 的"首个匹配即返回"（`Registry.py:323-325`）把证据静默归到列表序靠前者，**归错目标完全取决于 lf 列表的物理顺序，无任何冲突提示**。

### F4 `.lower()` ≠ Windows 大小写不敏感 —— 与兼容调用的双向分歧

同一样本中的折叠探针：

| 查询 | python-registry 结果 | Windows（RtlUpcaseUnicodeString 语义） |
|---|---|---|
| `open('Special')` 对键 `ſpecial`（U+017F） | **NotFound** | 匹配（ſ 大写化为 S）→ **漏报** |
| `open('ksign')` 对键 `Ksign`（U+212A 开尔文符号） | **命中**（`'K'.lower()=='k'`） | 不匹配（k 大写化为 U+004B，≠ U+212A）→ **误报** |

`Registry.py:324` 与 `Registry.py:350` 用 Python `.lower()` 模拟 Windows 的不敏感比较，但 Windows 用的是**大写化**表。对含特殊折叠关系的 Unicode 名称，同一查询在取证工具与在 Windows 上得到相反结果：以 Windows 行为为准绳的交叉核验会得出"工具多报/漏报证据"的结论。

### F5 内嵌空字符 —— 名称孪生碰撞 + 值数据两级截断

样本：`nul_separator.hive`

1. **键名孪生**：`Visible\x00Hidden`（UTF-16）与 `Visible`（压缩）是两个独立 NK 记录（偏移 `0x107c` vs `0x10ec`）。本库能区分（`subkey('Visible\x00Hidden')` 命中前者），但任何按 C 字符串截断 NUL 的展示/导出层会把两者都显示为 `ROOT\Visible`——**报告层面两条证据被归到同一个键**。
2. **值名孪生**：`Val\x00Suffix` 与 `Val` 同理；`value('Val')` 只命中后者，前者在截断式工具中不可见。
3. **RegSZ 数据截断（符合预期）**：`TruncData` 的原始数据 `abc\x00def` 经 `decode_utf16le()` 返回 `'abc'`，`def` 丢失。
4. **`decode_utf16le()` 启发式误判（超预期缺陷）**：`CjkData` 的原始数据为 `'abcÀ一def\x00'`（`61 00 62 00 63 00 C0 00 00 4E 64 ...`）。U+00C0（À）后接 U+4E00（一）恰好产生字节序列 `C0 00 00 4E`，其中的 `00 00` 被 `RegistryParse.py:792-804` 误判为字符串结尾，返回 `'abcÀ一'`——**终止符之前的合法数据 `def` 被静默丢弃**。只有显式 `value(overrun=16)` 才能取回完整内容（实测返回 `'abcÀ一def\x00'`）。任何"Latin-1 补充字符（U+00xx）后紧跟低字节为 0x00 的字符（U+xx00，如 一/丁/䀀 等大量 CJK）"的字符串都触发此缺陷，这在多语言值数据中并非罕见组合。

### F6 名称内嵌路径分隔符 —— `path()` 与 `find_key()` 不可逆，查找归到另一个键

同一样本：单键 `a\b`（名称含反斜杠，NK 偏移 `0x1144`）与嵌套键 `a`→`b`（NK 偏移 `0x11f4`）共存。

实测（`probe_extra.py` B 组）：

```
单键 'a\b'  path() = 'ROOT\a\b'
嵌套 a->b  path() = 'ROOT\a\b'        # 两个不同的键，展示路径完全相同
open('a\b') -> 解析到嵌套键（0x11f4）  # find_key 按 '\' 分段，永远到不了单键
```

`path()`（`RegistryParse.py:1560`）用 `'\\'` 直接拼接而不转义，`find_key()`（`Registry.py:363`）用 `partition("\\")` 拆分，二者对含分隔符的名称不互逆。**后果**：取证报告若按 `path()` 记录证据位置，读者用该路径重新定位时拿到的是另一个键的数据——这是最直接意义上的"证据归错键"。注意 round-trip 自检（比较重新打开后的 `path()` 字符串）**无法发现此问题**，因为两个键的路径字符串本来就相等；必须比较 NK 记录偏移才能区分。

### F7 字面值名 `"(default)"` 遮蔽真默认值 —— 大小写相关的路由不一致

样本：`default_shadow.hive`（真默认值 = `REAL-DEFAULT`，另有一名字为 `(default)` 的值 = `NAMED-(default)`）

实测（`probe_extra.py` C 组）：

```
枚举:            两个值都显示为 '(default)'，无法区分
value('(default)') -> REAL-DEFAULT      # Registry.py:346 把查询改写为空名
value('')          -> REAL-DEFAULT
value('(DEFAULT)') -> NAMED-(default)   # 不触发硬编码改写，走 .lower() 比较
value('(Default)') -> NAMED-(default)
```

`Registry.py:346-347` 的特判只认精确小写 `"(default)"`，而后续比较却是大小写不敏感的——**同一个逻辑实体，仅因查询串大小写不同被路由到两个不同的值**。名为 `(default)` 的值在精确查询下被真默认值遮蔽，枚举输出中两者又显示为同名，属于展示层与查找层双重归属混乱。

---

## 3. 哪些输入会把证据归到错误的键（判定汇总）

| # | 输入特征 | 归错机制 | 严重度 |
|---|---|---|---|
| 1 | 名称含 `'\\'` 的键 + 同形嵌套路径 | `path()` 文本相同，`open()` 恒解析到嵌套键（F6） | 高：报告路径指向错误键且无告警 |
| 2 | 仅大小写不同的重复键/值（删除残留、对抗构造） | 首个匹配即返回，lf 物理序决定归属（F3） | 高：静默归错，枚举才能发现 |
| 3 | 值名恰为 `(default)` | 查询被硬编码改写，路由随大小写摇摆（F7） | 高：同一逻辑查询命中不同值 |
| 4 | COMP_NAME 标志与内容不匹配 | 解码出含 NUL 的名称或 CJK 乱码，身份错乱（F1） | 中：键身份丢失但通常伴随可见异常 |
| 5 | 名称/数据内嵌 NUL | 截断式展示把孪生记录合并显示（F5-1/2/3） | 中：取决于下游工具 |
| 6 | RegSZ 数据含 `U+00xx` + `U+xx00` 相邻对 | `decode_utf16le` 启发式提前截断（F5-4） | 中：静默丢数据，无异常 |
| 7 | 孤立代理项名称 | 整键不可达 + 毒化兄弟键枚举与查找（F2） | 中：可见性丧失而非静默归错 |
| 8 | 含特殊折叠字符（ſ、K 等）的名称 | 与 Windows 语义双向分歧（F4） | 低-中：跨工具交叉核验时结论冲突 |

---

## 4. 原始名称与展示名称的保留边界

实证表明，**解码后的 `str` 不足以作为证据身份**：F1 中两个不同原始记录可解码出同一字符串，F6 中两个不同键产生同一路径字符串，F5 中截断式展示把不同记录合并。建议的保留边界：

**必须作为"原始名称"保留（身份层，用于归属与核验）**：
- NK/VK 的原始名称字节（`unpack_string(0x4C, name_length)` / `unpack_string(0x14, name_length)`）；
- 名称标志位（NK `flags & 0x20`，VK `flags & 0x01`）与声明的名称长度；
- NK 记录在 hive 中的偏移量——这是唯一在 F3/F5/F6 全部场景下都能区分记录的身份标识（本报告 B 组探针即用偏移 `0x1144` vs `0x11f4` 区分了两个 `ROOT\a\b`）。

**可作为"展示名称"（呈现层，仅供人读）**：
- 按标志位解码的字符串，但须附带解码质量标记（是否触发异常、是否含 NUL/代理项/分隔符）；
- 路径字符串只能作为展示，不能作为重新定位的键——重新定位必须走"父链偏移序列"或对每段名称做精确字节匹配。

边界原则：**任何一次有损变换（解码、截断、大小写折叠、分隔符拼接）之后的结果都不得回灌到身份层**。当前库在 `subkey()`/`value()` 中用 `.lower()` 比较、在 `value()` 中改写 `"(default)"`，都是把展示层语义回灌到了查找层。

---

## 5. 查找歧义对兼容调用的影响

`subkey()`、`value()`、`find_key()`、`open()` 是下游工具（含本仓库 `samples/` 下全部脚本）的兼容入口，歧义通过它们放大：

1. **结果不确定性**：F3 中同一查询的返回值取决于 lf 列表物理顺序。hive 被重组（reorganize）或经事务日志回放后列表顺序可变，**同一工具对同一逻辑 hive 的两次分析可给出不同归属**，且无可复现性告警。
2. **异常契约改变**：F2 中查询不存在键时，调用方期望的 `RegistryKeyNotFoundException` 被 `UnicodeDecodeError` 取代。以 `try/except RegistryKeyNotFoundException` 做"键是否存在"探测的兼容代码（如 `samples/regfetch.py:49` 的模式）会把"存在但名称损坏"误判为程序错误，或在上层被笼统吞掉。
3. **与 Windows API 的语义漂移**：F4 表明 `.lower()` 比较与 Windows 大写化比较存在双向分歧。依赖"取证工具结果应与 regedit/WinAPI 一致"假设的交叉核验流程，会在含特殊折叠字符的键上得到系统性冲突。
4. **路径不可重定位**：F6 中 `open(key.path())` 不保证回到 `key`。任何"先导出路径、后按路径复核"的两阶段工作流在此类键上静默复核了错误的对象。
5. **`(default)` 特判的大小写不对称**（F7）：`value("(default)")` 与 `value("(DEFAULT)")` 命中不同值，批量查询工具若对查询串做过大小写规范化，结果会与交互式查询不一致。

---

## 6. 基于本地 Hive 样本的核验判据

以下判据均可通过重跑 §0 的三条命令复核，期望输出引自 `analysis_output.txt` / `probe_extra_output.txt`：

**归属正确性**
- C1（F6）：`nul_separator.hive` 中 `open('a\\b')._nkrecord.offset()` == 嵌套键偏移（当前 `0x11f4`），且 ≠ 单键 `'a\b'` 的偏移（`0x1144`）。**若修复，应能通过字节级名称匹配定位到 `0x1144`。**
- C2（F3）：`case_collision.hive` 中 `open('EVIDENCE').value('Marker').value()` 当前恒为 `'first-in-list'`；修复后应对大小写精确匹配的查询优先返回精确键，或对多匹配抛出冲突告警。
- C3（F7）：`default_shadow.hive` 中 `value('(default)')` 与 `value('(DEFAULT)')` 当前命中不同值；修复后二者应一致，且名为 `(default)` 的值可通过某 API 无歧义获取。

**原始/展示边界**
- C4（F1）：`compressed_names.hive` 的 `FlagLie` 键，修复后应暴露"标志位与内容不一致"告警（如压缩名含 `0x00` 字节即告警），而非静默解码出含 NUL 的名称。
- C5（F5-4）：`CjkData` 值，修复后 `value()` 应返回完整 `'abcÀ一def'`（当前返回 `'abcÀ一'`）。判据即 `value() == 'abcÀ一def'`。

**健壮性**
- C6（F2）：`surrogate_names.hive` 中对不存在键的查询应抛 `RegistryKeyNotFoundException` 而非 `UnicodeDecodeError`；`[k.name() for k in root.subkeys()]` 不应因单个毒键整体失败（应对单键降级为替换字符或原始字节表示）。
- C7（F1-OddLen）：奇数长度 UTF-16 名称应解码为"截断字符 + 告警"，而非让整个键不可达。

**交叉一致性**
- C8（F4）：构造查询集 `{Special, ſpecial, Ksign, ksign, KSIGN}`，修复后工具应提供与 Windows 大写化语义一致的比较模式（或明确文档化差异），使 `ſpecial` 能被 `Special` 命中而 `Ksign`（U+212A）不被 `ksign` 命中。

---

## 7. 改进建议

按优先级排序（均指向本仓库具体位置）：

1. **查找层去歧义**（治 F3/F6/F7，最高优先）
   - `RegistryKey.subkey()`/`value()`（`Registry.py:314-326`、`340-354`）：收集全部大小写不敏感匹配；若多于一条，优先返回**字节级精确匹配**者，仍有多条时抛出新的 `RegistryAmbiguousNameException`（携带全部候选的 NK/VK 偏移），而非静默返回列表首项。
   - 删除 `Registry.py:346-347` 的 `"(default)"` 硬编码改写，改为：空串查询匹配无名值，非空查询只做名称比较；无名值的展示名 `"(default)"` 仅保留在 `RegistryValue.name()` 展示层。
2. **名称解码防御**（治 F1/F2/F5-4）
   - `NKRecord.name()`/`VKRecord.name()`：压缩名称解码前校验不含 `0x00` 字节；UTF-16 名称校验长度为偶数；解码改用 `errors='replace'`（或新增 `raw_name()` API 返回原始字节 + 标志位），使单键损坏不扩散为整分支不可枚举。
   - 重写 `decode_utf16le()`（`RegistryParse.py:778-809`）：按 UTF-16 码元边界扫描 `00 00` 终止符（仅在偶数偏移处判定），或干脆按声明长度解码后仅截去**末尾**终止符，消除 `U+00xx`+`U+xx00` 相邻对的误判。
   - 新增 `NKRecord.raw_name()` / `VKRecord.raw_name()`，返回 `(raw_bytes, is_compressed)` 元组，为身份层提供不经过有损解码的锚点。
3. **路径可重定位**（治 F6）
   - `NKRecord.path()` 对含 `'\\'`/`'\x00'` 的名称段做显式转义或标注；同时提供 `Registry.open_by_offsets()` 或精确匹配模式的 `find_key(exact=True)`（按原始字节比较），使"导出→复核"工作流有可靠的重定位入口。
4. **Windows 语义对齐**（治 F4）
   - 将 `.lower()` 比较替换为模拟 Windows 大写化的比较（如 `str.upper()` 并文档化残余差异，或引入 `unicodedata` 全大小写折叠对照表），并在文档中明确与 WinAPI 的已知差异字符集。
5. **取证输出建议**（面向工具使用者）
   - 报告证据位置时同时记录 `path()` 与 NK 记录偏移；对含 NUL、代理项、分隔符、大小写重复的名称，输出原始字节的 hex 转储而非仅解码字符串；枚举（`subkeys()`/`values()`）与按名查找（`subkey()`/`value()`）结果应交叉比对，二者不一致即视为归属风险信号。

---

## 附：样本与脚本清单

| 文件 | 作用 |
|---|---|
| `analysis/name_ambiguity/hivebuilder.py` | 最小 REGF/HBIN/NK/VK/LF hive 构造器 |
| `analysis/name_ambiguity/build_samples.py` | 生成 5 个样本 hive |
| `analysis/name_ambiguity/analyze_samples.py` | 主分析：四层追踪 + 查找/展示/round-trip 测试 |
| `analysis/name_ambiguity/probe_extra.py` | 补充探针：崩溃传播、偏移身份、`(default)` 大小写路由 |
| `analysis/name_ambiguity/hives/*.hive` | 样本：compressed_names / surrogate_names / case_collision / nul_separator / default_shadow |
| `analysis/name_ambiguity/analysis_output.txt`、`probe_extra_output.txt` | 实测输出（本报告全部结论的原始证据） |
