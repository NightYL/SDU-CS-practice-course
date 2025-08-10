from PIL import Image
import numpy as np


def string_to_ascii_binary(text):
    """
    将字符串转换为ASCII码对应的二进制字符串
    每个字符转换为8位二进制（ASCII码范围0-127）
    添加16位结束标记'1111111111111111'
    """
    binary = []
    for char in text:
        # 获取字符的ASCII码值
        ascii_code = ord(char)
        # 转换为8位二进制字符串，不足8位前面补0
        binary.append(format(ascii_code, '08b'))
    # 拼接所有二进制，并添加结束标记
    return ''.join(binary) + '1111111111111111'


def ascii_binary_to_string(binary):
    """
    将二进制字符串转换回原始字符串
    识别结束标记并忽略之后的内容
    """
    # 查找结束标记
    end_idx = binary.find('1111111111111111')
    if end_idx != -1:
        binary = binary[:end_idx]

    # 确保二进制长度是8的倍数
    binary = binary[:len(binary) - (len(binary) % 8)]

    # 每8位转换为一个ASCII字符
    text = []
    for i in range(0, len(binary), 8):
        byte = binary[i:i + 8]
        # 将8位二进制转换为整数（ASCII码）
        ascii_code = int(byte, 2)
        # 转换为字符
        text.append(chr(ascii_code))

    return ''.join(text)


def embed_ascii_watermark(original_path, text, output_path):
    """
    嵌入水印：将字符串转换为ASCII二进制后嵌入图像
    每个RGB通道使用最后两位存储2位信息，每个像素可存储6位
    """
    # 打开图像并转换为数组
    original_img = Image.open(original_path).convert('RGB')
    img_array = np.array(original_img, dtype=np.uint8)
    height, width, _ = img_array.shape

    # 将文本转换为ASCII二进制
    binary_data = string_to_ascii_binary(text)
    data_length = len(binary_data)

    # 计算最大可存储比特数（每个像素6位）
    max_bits = height * width * 6
    if data_length > max_bits:
        raise ValueError(f"文本过长！需要{data_length}位，图像仅能存储{max_bits}位")

    # 复制原始数组用于修改
    watermarked_array = img_array.copy()
    bit_index = 0  # 当前处理的二进制位索引

    for i in range(height):
        if bit_index >= data_length:
            break
        for j in range(width):
            if bit_index >= data_length:
                break

            # 为当前像素准备6位待嵌入信息（不足6位则用0补齐）
            bits = []
            for _ in range(6):
                if bit_index < data_length:
                    bits.append(binary_data[bit_index])
                    bit_index += 1
                else:
                    bits.append('0')  # 填充0

            # 按通道分配：R通道存前2位，G通道存中间2位，B通道存最后2位
            r_bits = bits[0:2]
            g_bits = bits[2:4]
            b_bits = bits[4:6]

            # 处理R通道：替换最后两位
            r_val = img_array[i, j, 0]
            r_bin = list(np.binary_repr(r_val, width=8))
            r_bin[-2:] = r_bits  # 替换最后两位
            watermarked_array[i, j, 0] = int(''.join(r_bin), 2)

            # 处理G通道：替换最后两位
            g_val = img_array[i, j, 1]
            g_bin = list(np.binary_repr(g_val, width=8))
            g_bin[-2:] = g_bits  # 替换最后两位
            watermarked_array[i, j, 1] = int(''.join(g_bin), 2)

            # 处理B通道：替换最后两位
            b_val = img_array[i, j, 2]
            b_bin = list(np.binary_repr(b_val, width=8))
            b_bin[-2:] = b_bits  # 替换最后两位
            watermarked_array[i, j, 2] = int(''.join(b_bin), 2)

    # 保存结果
    watermarked_img = Image.fromarray(watermarked_array)
    watermarked_img.save(output_path)
    print(f"成功嵌入{data_length}位ASCII二进制信息（对应{len(text)}个字符）")
    return watermarked_img


def extract_ascii_watermark(watermarked_path):
    """提取水印：从图像中提取二进制数据并转换回字符串"""
    # 打开图像并转换为数组
    watermarked_img = Image.open(watermarked_path).convert('RGB')
    img_array = np.array(watermarked_img, dtype=np.uint8)
    height, width, _ = img_array.shape

    # 提取所有二进制位
    binary_data = []
    for i in range(height):
        for j in range(width):
            # 提取R通道最后两位
            r_val = img_array[i, j, 0]
            r_bin = np.binary_repr(r_val, width=8)
            binary_data.append(r_bin[-2:])  # 取最后两位

            # 提取G通道最后两位
            g_val = img_array[i, j, 1]
            g_bin = np.binary_repr(g_val, width=8)
            binary_data.append(g_bin[-2:])  # 取最后两位

            # 提取B通道最后两位
            b_val = img_array[i, j, 2]
            b_bin = np.binary_repr(b_val, width=8)
            binary_data.append(b_bin[-2:])  # 取最后两位

    # 拼接所有二进制位并转换为字符串
    binary_str = ''.join(binary_data)
    return ascii_binary_to_string(binary_str)


# 示例用法
if __name__ == "__main__":
    # 要嵌入的文本
    secret_text = "Hello,World"

    # 嵌入水印
    embed_ascii_watermark(
        original_path = "your_original_path",
        text=secret_text,
        output_path = "ascii_watermarked.png"
    )

    # 提取水印
    extracted_text = extract_ascii_watermark("ascii_watermarked.png")
    print("提取的文本内容：")
    print(extracted_text)

