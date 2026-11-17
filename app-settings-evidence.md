# settings.dat 复合值取证解释：原始字节、类型化结果与时间精度

**分析对象**：python-registry 1.3.1（`Registry/__init__.py:19`），核心代码
`Registry/RegistryParse.py`（VK 记录与 Hive 数据寻址）、`Registry/SettingsParse.py`
（ApplicationDataCompositeValue 反序列化）。
**证据基础**：源码逐行审阅 + 用合成二进制记录进行的行为探针；仓库只有一个压平提交，
无法做历史回归对比。`tests/` 下可运行的 unittest 用例 6 个全部通过，`test_parse.py`、
`test_parse_timestamp.py` 为 pytest 风格（当前环境未安装 pytest，未运行），
且没有任何 `settings.dat` 素材或复合值用例；因此下面关于“真实样本上如何表现”的结论都只到
“代码路径可证”这一级，不外推。`test_parse_timestamp.py` 的注释本身就记录了两条路径的差异：
`131132256000418650` 在 float 路径得 `…041864`、在 Decimal 路径得 `…041865`（本次已复现），
与第 1.4 节结论一致。探针环境为 Python 3.12。

---

## 0. 数据路径总览（先分清三层）

一个 `vk` 记录被读取时，实际经过三个彼此独立的解释点：

1. **Hive 层**：`VKRecord` 给出名称、原始类型 dword、声明长度、数据单元偏移，
   并通过 `raw_data()` 切出字节（`RegistryParse.py:964-1138`）。
2. **复合值层**：`data()` 对 `0x100` 命名空间的类型先无条件去掉末尾 8 字节，
   再把剩余流交给 `SettingsParse.ParseAppDataCompositeValue()`（`RegistryParse.py:1203-1212`）。
3. **时间解释层**：`VKRecord.timestamp()` 独立地再次取 `raw_data()[-8:]`，
   用另一套（Decimal）时间函数解释（`RegistryParse.py:995-1002`）；
   而复合流内部的 `RegDateTimeOffset` 使用 float 路径（`SettingsParse.py:73-75,122`）。

关键事实：`0x100` 位是**类型命名空间标记**（顶层类型 `0x101-0x11F`，流内子类型不带 `0x100`，
见 `SettingsParse.py:37-40`），不是“存在时间戳”的标志；但 `has_timestamp()` 把它当成了后者的判据
（`RegistryParse.py:989-993`）。三层对同一段末尾字节各自作出解释，这是本主题所有歧义的根源。

---

## 1. 原始字节、类型化结果、时间精度如何一同保留

### 1.1 三层各自能承载什么

| 层 | 可保存的内容 | 不应承担的内容 |
|---|---|---|
| 原始字节层 | VK 头字段（名称长度/标志/类型 dword/声明长度/数据字段）、数据单元头部与偏移、声明长度范围内的 payload、末尾 8 字节、数据单元实际可用字节数 | 语义、类型合法性、条目边界之外的归属 |
| 类型化结果层 | 名称、`data_type()` 掩码后的类型、逐条目解码值、解析状态/异常类型 | 被丢弃的重复条目、未成功条目、未知子类型的原始字节（现实现返回字符串化的 bytes） |
| 时间解释层 | 原始 8 字节/qword ticks、换算所用纪元与分辨率、换算后的 datetime、精度损失说明 | 该 8 字节是否真的是时间戳（当前 API 无法证明） |

**原则**：三者必须并列保存，不能以类型化结果替代原始字节，也不能只保存 datetime 而丢掉 qword。
`datetime` 只有微秒分辨率，FILETIME 是 100ns 分辨率；换算本身就是一次有损、且实现相关的投影。

### 1.2 归属到“原始键值”的字节边界

可以较有把握归属的字节，是以下**由记录自身字段闭合定义**的区间：

- VK 记录头：`vk` 标志、`0x2` 名称长度、`0x4` 数据长度、`0x8` 内联字段、`0xC` 类型、`0x10` 标志、
  `0x14` 起的名称（`RegistryParse.py:817-832,964-1032`）。
- 数据位置：`raw_data_length() >= 0x80000000` 或 `< 5` 时视为内联；否则 `0x8` 是相对首个 HBIN 的偏移
  （`RegistryParse.py:1025-1032`）。
- 数据单元：`HBINCell` 的 4 字节有符号大小 + payload（`RegistryParse.py:547-613`）。
- 大数据的 `db` → `db` 间接块 → 多个 chunk（`RegistryParse.py:710-775`）。

以下情形**不能**再声称某段字节“属于该值”：

1. **声明长度大于数据单元可用字节**。resident/复合分支按声明长度切片
   （`RegistryParse.py:1056-1058,1079,1094`），不检查数据单元大小；只要文件还有字节，
   就**静默并入后继单元、记录或零填充**，返回长度等于声明长度（探针：单元内 20 字节 payload、
   声明 100 时 `raw_data()` 仍返回 100 字节，多出的 80 字节来自后续区域；声明 4000 时读到 4000 字节）。
   只有在缓冲区末尾才会被 Python 切片静默截短，而返回值本身不带“是否截短”的信息。
2. **内联复合值的高位长度声明超过 4 字节**。`raw_data()` 从 VK+0x8 起切 `data_length` 字节
   （`RegistryParse.py:1067-1069`），声明 `0x80000010` 时会把 `0x8` 内联字段、
   `0xC` 类型、`0x10` 标志、`0x12` 保留字、`0x14` 起的名称区一起返回
   （探针原始 16 字节：`44332211 0b010000 0100 0000 00000000`）；其中 `0b010000` 是 VK 自己的
   类型字段（0x10B），`0100` 是标志字，都不属于值数据。
3. **内联复合值声明长度 < 5**。`data_offset()` 返回 VK+0x8（`RegistryParse.py:1029-1030`），
   但复合值分支随后又加 4 再切片（`RegistryParse.py:1079`），实际读到的是 VK+0xC 的类型 dword；
   探针中一个 4 字节内联 `uint32` 的 `raw_data()` 返回 `05010000`（类型字段），不是 payload。
4. **名称长度越过 VK 单元边界**。`unpack_string(0x14, name_length)` 不校验记录边界
   （`RegistryParse.py:282-289,976-987`）；探针中声明 8、实际 2 字节时，名称被补成 8 字节并包含后继字节。
   只有缓冲区真的不够长时才会抛 `struct.error`。
5. **大数据 chunk 未按单元实际大小记账**。`DBIndirectBlock.large_data()` 每轮取
   `min(0x3fd8, length)` 而非该 chunk 的可读字节数（`RegistryParse.py:728-742`）；
   合成小 chunk 上请求 16600 字节只返回 4352 字节，边界处混入了下一单元的 4 字节大小字段，
   且没有错误提示。真实大值通常 chunk 恰好 0x3fd8，但损坏时上述账目不可信。

因此“原始字节”本身也要带**来源区间和截断标志**才有证据价值；不能把 `raw_data()` 的返回值默认当作完整值。

### 1.3 部分字段失败时仍可归属的内容

`RegistryValue` 的名称、类型和 `raw_data()` 与 `value()` 是分离的（`Registry.py:113-236`），
所以当类型化解码失败时，以下内容仍然成立（前提是 Hive 层没被上面第 1.2 节的边界问题污染）：

- 值名称（解码成功时）及名称长度/ASCII 标志；
- 原始类型 dword 和 `data_type()`（`0x0FFF` 掩码后）；
- 声明长度与 `data_length()`（去掉 `0x80000000` 标志后的长度）；
- 数据单元偏移/大小、实际读到的字节序列及其长度；
- 末尾 8 字节（若声明长度 ≥ 8），作为**未解释字节**保留，而不是时间戳；
- 异常类型（`struct.error` / `UnicodeDecodeError` / `IndexError` / `RecursionError`），
  这些都不是 `RegistryException` 的子类，调用方需广泛捕获。

反过来，以下内容在部分失败时**不能**归属：

- **整个复合流**：`ParseAppDataCompositeStream()` 没有逐条 try；任一条目抛异常，
  之前已解出的条目也随调用栈丢弃，调用方拿不到部分字典（`SettingsParse.py:143-169`）。
- **条目偏移与条目类型**：返回字典只保存 `name -> value`，不保存起始偏移、声明长度、类型
  （`SettingsParse.py:162-163`），事后无法从结果重建字节归属。
- **重复名称**：`composite_data[item_name] = value` 后者覆盖前者；探针 `{'x': 2}`，
  前一条 `x` 在类型化结果中不可见（原始字节里仍在）。名称大小写不归一，键区分大小写。
- **被未知子类型“吞掉”的字节**：未知类型打印到 stdout 后返回 `str(data)`
  （`SettingsParse.py:138-140`），这是带引号/转义的显示文本，不是可回转的原始字节；
  同时污染按行读取的取证输出（探针捕获到两行 `UNKNOWN TYPE FOUND...`）。
- **条目边界处的静默缺失**：流恰好在 8 字节对齐的条目边界截断时，`ParseAppDataCompositeStream()`
  正常返回较少条目，无异常（探针：两项流截断为一项）；无法仅凭返回值区分“本来只有一项”。

### 1.4 时间精度的保留与失真

**原始精度**：FILETIME 为 100ns tick；`RegTimeSpan` 为 100ns tick（`SettingsParse.py:54-55`）。
**输出精度**：`datetime` 只到微秒。`RegistryParse.parse_timestamp()` 用 `Decimal` 做
`ticks*1e6/1e7` 并按 `ROUND_HALF_EVEN` 量化到 µs（`RegistryParse.py:99-116`），
所以 100ns 位在类型化结果中必然丢失，且丢失方式由实现固定。
`SettingsParse.parse_windows_timestamp()` 则走 `float(qword)*1e-7` + `utcfromtimestamp`
（`SettingsParse.py:73-75`），多了一层二进制浮点误差；超出 `datetime` 可表示范围时抛
`ValueError`（如 `2^63-1` → `year 30828 is out of range`），`float` 极端值也可能落到
`OverflowError`。

实测（合成 qword，非真实样本）：

- 12 万个 `randrange(0, 2**63)` 抽样中约 **26.7%** 的 `datetime` 与 Decimal 路径不同，最大偏差 **53 µs**；
- 2022 年前后、步长 16 ticks 的 10 万个样本：偏差 0–2 µs，**58.5%** 不同
  （混合 1970/2022 窗口的 20 万样本为 0–3 µs、63%）；
- 相差 5 个 tick（0.5 µs）的两个值在 float 路径上 **100% 合并为同一 datetime**；
- `RegTimeSpan` 在 `2^63-1` 时相对精确值偏 **42 µs**（按 tick/10 与 half-even 量化比较）；
  负 tick（如 −1 天）被按无符号解释，得到约 2,135 万天（`SettingsParse.py:123` 用 `<Q`，没有符号语义）。

**同一时刻、两条路径**：复合流内部的 `RegDateTimeOffset` 用 float（`SettingsParse.py:122`），
顶层 `RegistryValue.timestamp()` 用 Decimal（`RegistryParse.py:1001`）。
同一 ticks 可能相差数 µs；跨来源比较时间时必须标注“经由哪条路径”。

**时间戳归属的三条硬规则**：

1. 永远保存原始 8 字节/qword（十六进制），并把 datetime 标为“派生值 + 量化规则 + 来源路径”。
2. 末尾 8 字节是否为 trailer **不可由类型位证明**。`has_timestamp()` 只要求
   `data_type & 0x100` 且声明长度 ≥ 8（`RegistryParse.py:989-993`），而所有 `0x1xx` 类型都满足前者。
   探针：一个 10 字节的 `RegUnicodeString`（`0x10C`，内容 `"ABCDE"`，没有 trailer）被判为
   `has_timestamp()==True`，`value()` 去掉末 8 字节后只剩 `'A'`，`timestamp()` 把 `"BCDE\0..."` 当时刻。
3. **声明的“值长度”不含 trailer 时会伪造时间戳**：把一个 24 字节的合法复合流直接作为值
   （无 trailer）时，`data()` 去掉最后 8 字节导致解码失败，`timestamp()` 却成功返回
   `1601-01-01 00:01:49.486164` —— 它读的是最后一条目的 payload 字节 `4443424100000000`。
   这是“类型化时间结果不可归属”的最直观证据。

此外，`overrun` 参数会破坏 trailer 的“最后 8 字节”前提：`data(overrun=2)` 对同一值
可能直接抛 `struct.error`，而 `raw_data(overrun=2)` 的末 8 字节已包含越界读入的字节，
不再等于声明的时间戳（探针：原末 8 字节 `…0080209b cb82d801`，overrun 后变为
`209bcb82 d8010000`，多出 2 个越界字节、丢掉原末 2 字节）。

### 1.5 建议的证据记录结构（按值）

建议每条值至少保存：

```yaml
value:
  key_path: "<hive>/<path>"
  name_utf16_or_bytes: "<decoded name | hex of raw name>"
  type_dword_raw: "0x0000010D"
  type_masked: "0x10D"
  declared_length_raw: "0x8000001C"
  declared_length_effective: 28
  storage: "inline-0x8 | resident-cell | db-chunked"
  data_cell_offset: "0x1234"
  data_cell_size: 0x40
  payload_hex: "...."          # 只标注实际读到的区间
  payload_truncated: false     # 声明长度 > 可用字节
  trailer_hex: "...."          # 仅作为候选，不标为 timestamp
  items:
    - name: "a"
      type_stream_id: "0x005"
      item_offset: 0
      item_length: 24
      data_hex: "07000000"
      typed: 7
      status: "ok | struct.error | UnicodeDecodeError | unknown-subtype"
  typed_value_error: null
  timestamp_raw_ticks: "0x0...."   # 若使用，必须带来源
  timestamp_source: "value_trailer | composite-item | none"
  timestamp_precision: "source=100ns; output=1us; path=decimal|float"
  parse_notes: ["has_timestamp 仅由类型位与长度推断", "无 trailer 证据"]
```

对每个失败条目都要保留 `item_offset/item_length/data_hex/status`；这比保存“部分字典”更可靠，
因为当前 API 一旦抛错就什么都不返回。

---

## 2. 复合值与 Hive 读取的责任边界

### 2.1 边界应当如何划分

**Hive 层（`RegistryParse`）应负责“字节从哪来、到哪去”**：

- 解析 VK 头，验证名称/数据长度不越过自身单元；
- 区分内联（0x8 字段）、resident cell、`db` 大块，给出精确区间与实际可用长度；
- 比较“声明长度”和“实际可交付长度”，把截断/越界显式上报；
- 只向复合层交付：**纯 payload 字节 + 是否含 8 字节 trailer 的候选/置信度**，
  不替复合层做时间或条目语义决定。

**复合值层（`SettingsParse`）应负责“这串自包含字节如何解释”**：

- 只处理传入的 buffer，不访问 Hive、不依赖键路径；
- 对每条目做边界、长度、类型校验，逐条目返回成功/失败与字节区间；
- 不把未知类型转换为显示字符串充当值；
- 不决定 trailer 是否存在（由调用方/上层给出候选，或由本层做双解析并报告歧义）。

### 2.2 当前实现越界的地方

| 位置 | 行为 | 后果 |
|---|---|---|
| `RegistryParse.py:1210` | 对所有 `0x1xx` 类型无条件 `d = d[0:-8]` | 无 trailer、内联、截断值都被切掉 8 字节；10 字节字符串 `"ABCDE"` 变成 `'A'` |
| `RegistryParse.py:989-993` | `has_timestamp = type&0x100 and len>=8` | 把类型命名空间位当作 trailer 标志；任何 ≥8 字节的新式类型都“有时间戳” |
| `RegistryParse.py:995-1002` | `timestamp()` 独立读 `raw_data()[-8:]` | 与 `data()` 的去尾逻辑重复且不一致；`overrun`、截断、内联时读错字节 |
| `RegistryParse.py:1008,1211` | 先用 `0x0FFF` 去 DEVPROP 修饰位，再用 `0xEFF` 去 `0x100` | 数组修饰 `0x1104` 先变 `0x104`（标量 Int32），3 元素数组被解释成单值 11；`0x2004` 变普通 DWord |
| `RegistryParse.py:1029-1030,1067-1079` | 内联复合值的取址规则（0x8 起、却又 +4） | 高位内联声明 >4 字节会扫到 VK 头字段；<5 字节会读到 0xC 的类型字段 |
| `RegistryParse.py:1095-1123` | 其他已知类型对高位内联的处理各自为政 | `RegQWord` 把 0x8 当 cell 指针；`RegFileTime` 使用 `0x8+4` 与声明长度，实测可读出跨越整个伪造缓冲区的长串 |
| `SettingsParse.py:154-167` | `item_byte_len`、`item_name_len`、`data_size` 无任何一致性校验 | 长度为 0 时 `pos` 不前进：子类型能容忍空数据（Boolean/UnicodeString/数组）时 **静默死循环**，子类型需要数据时先抛 `struct.error`；对齐到下一个 8 字节后若读到全零头部，则进入 `unknown type 0x0` 分支并持续 `print`，形成“死循环 + 无界 stdout”（探针 1 秒内 >30MB）；名称长度大于条目时 `data_size` 为负，切片为空但继续解析；短声明会让下一条目从 payload 内部开始读 |
| `SettingsParse.py:158` | 名称 `decode('utf-16')` 未捕获异常 | 单个坏名称（孤立代理、奇数长度）使整个流失败，之前条目全部丢失 |
| `SettingsParse.py:84-88` | 字符串数组不校验元素长度是否越界/为偶数 | 声明 100、实际 2 字节时静默返回 `['A']`；零长度元素产生空串 |
| `SettingsParse.py:126-137` | 数组按声明大小构造，而非实际字节 | 声明 4、实际 1 字节的 bool 数组返回 `[False, True, True, True]`；4 字节实际数据 + 500 万声明长度可生成 500 万元素列表（约 0.5 s / 48 MB） |
| `SettingsParse.py:119` | 布尔取 `data[0:1] != b'\x00'` | 空数据返回 `True`；4 字节 `01 00 00 00` 只看首字节；`00 00 00 01` 返回 `False` |
| `SettingsParse.py:118` | `RegUnicodeChar` 只取前 2 字节并按 UTF-16 解码 | 代理对（4 字节）直接 `UnicodeDecodeError`；“char”不等于完整 Unicode 标量 |
| `SettingsParse.py:120` | 字符串 `decode('utf-16')` 保留内嵌 NUL、消费 BOM | BOM 会改变字节序解释；与数组的 `rstrip('\0')` 规则不一致 |
| `SettingsParse.py:121` | 嵌套复合值直接递归 | 深度约 500 触发 `RecursionError`（非 `RegistryException`）；损坏深嵌套使整个值失败 |
| `Registry.py:328-338,340-354` | `values()/value()` 只捕获 `RegistryStructureDoesNotExist` | 一个 `ParseException`/`struct.error` 可中断整个枚举，其他无关值也无法返回 |
| `RegistryParse.py:1274-1280` | `ValuesList.values()` 不检查 cell 是否 free，只校验 `vk` 标志 | 指向任意含 `vk` 字节的单元可被当成值；偏移无 Hive 边界复核 |
| `RegistryParse.py:1714-1725` | `cells()` 在 cell size 为 0 时原位重复 yield | 遍历任一损坏 Hive 时死循环（探针需靠调用方 break） |
| `RegistryParse.py:767-775` | `DBRecord.large_data()` 不验证间接块/cell 是否存在 | 损坏 `db` 指针可读到任意位置 |

### 2.3 可证实字段与不可推断信息

**仅凭本库与单个 Hive 字节可以证实的**：

- `vk` 标识、名称字节/长度/ASCII 标志（在长度未越界时）；
- 类型 dword（原始值、`0x0FFF` 后的值）；
- 声明数据长度、是否带 `0x80000000` 标志、存储形态（内联/单元/db）；
- 数据单元偏移与大小、实际读到的 payload 长度（以及是否小于声明）；
- 复合流中每条目头部的 12 字节、名称长度、声明条目长度、子类型码、条目数据区间
  （只有在不超过我们能证明的边界时）；
- 8 字节末尾候选字节（作为字节，不作为时间）；
- Hive 头校验和、序列号、HBIN 边界（`REGFBlock.recovery_required()`，`RegistryParse.py:449-501`）。

**不可推断、必须标注为未知的**：

- 末尾 8 字节究竟是时间戳还是 payload（`has_timestamp` 不是证据）；
- 缺失条目是“本来不存在”还是“流被截断”（尤其在 8 字节对齐边界）；
- 重复名称在写入时是否真的是两个不同条目（类型化结果只保留最后一个）；
- 未知子类型 `0x011-0x013` 的语义（代码刻意注释掉，见 `SettingsParse.py:125`）；
- 布尔、字符、数组在声明大小与实际大小不一致时的“真实值”；
- Hive 是否为 `settings.dat`：`hive_type()` 依赖内部 hive name 字符串
  （`Registry.py:405-434`），名称缺失/损坏即为 `UNKNOWN`，不能反证不是 settings.dat；
- 事务日志是否已应用：`Registry` 不自动合并日志，`RegistryLog` 需调用方显式使用
  （`Registry.py:383-396`，`RegistryLog.py:26-186`）；
- 值的修改时间是否等于用户/应用事件时间，甚至是否等于系统写入时间；
- Hive 修订是否完整：构造函数不检查校验和/序列号，`recovery_required()` 只提供状态而不阻止读取。

### 2.4 旧调用兼容取舍

现存调用面（从 `samples/` 可观察）：

- `regview.py`：对未知类型直接 `unicode(value.value())`；
- `test_dump.py`：用 `raw_data()` 做十六进制输出；
- `forensicating.py`、`reg_export.py`：按标准类型分派，假定 `value()` 返回标量/bytes；
- `RegistryKey.values()` 被当作稳定遍历接口；`raw_data(overrun)` 是公开参数。

因此任何“把复合值默认改为严格返回/抛错”的方案都会改变这些调用的错误面。可选路径：

| 方案 | 兼容性 | 取证收益 | 代价 |
|---|---|---|---|
| A. 纯增量 API：保留 `data()/timestamp()` 原行为，新增 `raw_payload()`、`composite_items()`（带偏移/类型/状态）、`timestamp_candidate()`、`trailer_hex` | 高 | 高；新代码可完整归因 | 旧 API 的歧义继续存在，文档必须显著标注 |
| B. 改变默认：仅当尾部可严格验证为 trailer 才剥离，否则抛错/返回原始字节 | 中低 | 阻止伪造时间戳和截断误解 | 无 ground truth 区分“真无 trailer”与“损坏/截断”；现有捕获面全变 |
| C. 返回 dict 子类/带元数据对象 | 中 | 兼容 `== dict`、`[...]` 等常见用法 | 类型检查、序列化、repr 行为改变；不等于“无歧义” |
| D. 增加 `strict=False` 参数，默认沿用旧行为，严格模式做逐条边界校验与显式异常/部分结果对象 | 高 | 高；可按调查需求切换 | API 面扩大；必须明确“默认模式不可用于结论性取证” |
| E. `RegistryKey.values()` 改为跳过坏值并收集错误 | 中 | 提高枚举可用性 | 静默隐藏损坏；改变“有值就返回”的语义；应作为新接口而非默认 |
| F. 在 `Registry` 模块导出 `0x1xx` 常量（当前只在 `RegistryParse`） | 高（纯增加） | 调用方可直接比较类型 | 极小 |

**推荐**：A + D。默认路径保持兼容，但文档明确“默认 `value()/timestamp()` 只是便捷投影”；
严格/取证接口逐值返回原始区间、条目状态、候选 trailer 与双解析结果。对会造成进程级故障的问题
（`SettingsParse` 的 0 长度死循环、无界输出、负长度、递归深度）应先加边界保护，
即便这会改变损坏输入上的异常类型——这属于安全性修复，不是语义变更。

**时间兼容**：把 `SettingsParse.parse_windows_timestamp` 从 float 改成 Decimal 会使约 27% 的
历史输出相差 0–53 µs，依赖精确 datetime 的调用方/快照会变化；更稳妥的是保留旧函数，
另提供返回 `(raw_ticks, datetime_decimal)` 的新函数，并在证据记录中标注来源。

**`overrun` 兼容**：`overrun` 对普通值是有意的越界读取；但复合值把“去掉最后 8 字节”与
“可能多读 overrun 字节”叠加，语义不可同时成立。建议在复合值上显式拒绝 `overrun>0`，
或在证据记录中把 overrun 后的末 8 字节标为“非 trailer”。

### 2.5 有限验证判据（能做什么、不能做什么）

对单个顶层复合值，建议按以下顺序做**可判定的结构检查**；任何一步失败，结论只能到“该步之前”：

1. `vk` 标志、名称长度不越过 VK 单元；
2. 声明长度与实际可交付长度一致；否则标记 `truncated`，禁止把超出部分当值内容；
3. 内联标志与长度自洽（高位内联长度 ≤4；`len<5` 的内联规则明确）；
4. 候选 A：`payload' = raw[:-8]`，候选 B：`payload' = raw`；对两者分别尝试：
   - 12 字节条目头完整；
   - `item_name_len*2` 在条目内、名称解码成功；
   - `item_byte_len >= 12 + (name_len+1)*2`；
   - `data_size >= 0` 且 `pos+data_size <= len(stream)`；
   - 每条目的下一个位置按 8 字节对齐后仍在流内；
   - 条目子类型 ∈ `0x001..0x01F`（或显式记录未知）；
   - 数组类型时 `data_size` 是元素宽度的整数倍；
   - 最终消费位置恰好等于 `len(payload')`（不允许尾部静默残余）。
5. 若 A、B 都通过：**歧义**，两者都记录，不选边；若只有 A 通过，可把末 8 字节标为“候选 trailer，
   结构一致”；若只有 B 通过，不能剥离时间戳；都失败则只保留原始字节；
6. 时间仅在“结构一致”基础上作为**候选**输出，并附：原始 ticks、纪元、分辨率、换算路径、
   datetime 可表示性（1601–9999）；超出范围即报告“不可换算”，保留 ticks；
7. 交叉印证只能作为弱证据：与 Hive 头 `modification_timestamp()`、同键其他值、日志链
   （`RegistryLog`）对照；不一致不代表伪造，一致也不证明语义。

**这些判据能证明**：字节区间、声明/实际长度一致性、条目边界、类型码、名称可解码性、
数组宽度一致性、Hive 校验和/序列号状态、日志是否可应用。
**不能证明**：某 8 字节的语义、缺失条目原因、重复条目历史、未知类型含义、值修改时间与事件时间的关系、
Hive 类型身份、Hive 是否已合并日志、字段是否被恶意构造但结构自洽。

---

## 3. 结论分级（按证据强度）

| 等级 | 陈述 | 依据 |
|---|---|---|
| 强 | `0x100` 位是类型命名空间；`has_timestamp` 由它和长度 ≥8 推断，不能证明 trailer 存在 | `RegistryParse.py:989-993`；`SettingsParse.py:37-40`；探针：无 trailer 的 10 字节 `0x10C` 被剥离 8 字节 |
| 强 | 无 trailer 的复合流会被剥掉末 8 字节，并可能从 payload 造出时间戳 | `RegistryParse.py:1210,1001`；探针 24 字节流 → `timestamp()=1601-01-01 00:01:49.486164` |
| 强 | 任一坏条目会使整条复合流无结果；重复名称只保留最后一个；未知子类型打印 stdout 并返回字符串化 bytes | `SettingsParse.py:138-140,162-169`；探针 |
| 强 | 0 长度条目导致死循环；小长度条目可无界输出；深嵌套触发 `RecursionError` | `SettingsParse.py:154-167,121`；探针 |
| 强 | 声明长度与实际字节不一致时静默截断/并入相邻字节，不产生异常 | `RegistryParse.py:1034-1138`；`SettingsParse.py:84-88`；探针 |
| 强 | 时间结果精度取决于路径：Decimal（顶层 `timestamp()`）vs float（复合内 `RegDateTimeOffset`），全范围最大偏差 53 µs，0.5 µs 间隔全部合并 | `RegistryParse.py:99-125`；`SettingsParse.py:73-75,122`；探针 |
| 中 | 大块数据 chunk 记账在损坏输入上有丢失/混入相邻头部的风险 | `RegistryParse.py:728-742`；合成探针返回长度小于请求且边界含 cell 头 |
| 中 | Hive 层不校验校验和/序列号、不自动应用日志，可能读到事务中间态 | `Registry.py:383-396`；`RegistryParse.py:486-501`；`RegistryLog` 需显式调用 |
| 弱/未知 | 真实 `settings.dat` 上的字段语义、时间戳含义、未知子类型含义 | 无样本、无测试；`SettingsParse.py:9` 自述“reverse engineered” |

**一句话结论**：在当前实现下，复合值的“类型化结果”不能独立作为证据；只有把
“VK 声明字段 + 实际交付字节区间 + 条目级解析状态 + 原始 ticks + 换算路径”一起保存，
才能把可证实部分与不可推断部分分开。时间戳必须始终被视为**候选字节**，直到结构验证给出
唯一解释为止。
