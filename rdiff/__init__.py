"""最小化 rsync 风格的二进制差分工具（不依赖任何现成差分库）。

三个子命令：
    signature baseline sig        生成基线签名
    delta     sig new patch       依据签名与新文件生成补丁（不读基线正文）
    apply     baseline patch out  依据冻结基线与补丁重建目标（不读新文件）
"""

VERSION = 1
BLOCK_SIZE = 256
MAX_FILE_SIZE = 32 * 1024
