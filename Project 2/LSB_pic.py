from PIL import Image
import numpy as np


def embed_watermark_rg(original_path, watermark_path, output_path):
    """
    在RGB图像的R通道嵌入水印信息

    参数:
        original_path: 原始图像路径
        watermark_path: 水印图像路径
        output_path: 嵌入水印后的图像保存路径
    """
    # 打开原始图像和水印图像
    original_img = Image.open(original_path).convert('RGB')  # 确保为RGB模式
    watermark_img = Image.open(watermark_path).convert('L')  # 水印转为灰度图

    # 确保水印图像尺寸不大于原始图像
    if (watermark_img.size[0] > original_img.size[0] or
            watermark_img.size[1] > original_img.size[1]):
        raise ValueError("水印图像尺寸不能大于原始图像尺寸")

    # 转为numpy数组以便操作
    original_array = np.array(original_img, dtype=np.uint8)
    watermark_array = np.array(watermark_img, dtype=np.uint8)

    # 获取图像尺寸
    w, h = watermark_array.shape
    orig_h, orig_w, _ = original_array.shape

    # 创建嵌入水印后的图像数组
    watermarked_array = original_array.copy()

    # 嵌入水印：使用R和G通道的最低有效位
    for i in range(w):
        for j in range(h):
            # 水印像素二值化（大于127视为1，否则为0）
            watermark_bit = 1 if watermark_array[i, j] > 127 else 0

            # 处理R通道：替换最低有效位
            r_val = original_array[i, j, 0]
            r_bin = list(np.binary_repr(r_val, width=8))
            r_bin[-1] = str(watermark_bit)  # 最低位存储bit_r
            watermarked_array[i, j, 0] = int(''.join(r_bin), 2)

    # 保存嵌入水印后的图像
    watermarked_img = Image.fromarray(watermarked_array)
    watermarked_img.save(output_path)

    return watermarked_img


def extract_watermark_rg(watermarked_path, watermark_path, output_path):
    """
    从RGB图像的R通道提取水印信息

    参数:
        watermarked_path: 含水印图像路径
        watermark_path: 水印图像路径
        output_path: 提取出的水印保存路径
    """
    # 获取水印图片大小
    watermark_img = Image.open(watermark_path).convert('L')  # 水印转为灰度图
    watermark_size = watermark_img.size[::-1]
    w, h = watermark_size

    # 打开含水印图像
    watermarked_img = Image.open(watermarked_path).convert('RGB')
    watermarked_array = np.array(watermarked_img, dtype=np.uint8)

    # 创建用于存储提取水印的数组
    extracted_array = np.zeros(watermark_size, dtype=np.uint8)

    # 提取水印
    for i in range(w):
        for j in range(h):
            # 从R通道提取最低有效位
            r_val = watermarked_array[i, j, 0]
            r_bin = np.binary_repr(r_val, width=8)
            lsb = int(r_bin[-1])  # 获取R通道最低位

            # 将提取的位转换为像素值（0或255，以便显示）
            extracted_array[i, j] = 255 if lsb == 1 else 0

    # 保存提取的水印
    extracted_img = Image.fromarray(extracted_array)
    extracted_img.save(output_path)

    return extracted_img


# 示例用法
if __name__ == "__main__":
    # 嵌入水印
    watermarked_img = embed_watermark_rg(
        original_path="your_original_path",  # 原始图像路径
        watermark_path="your_watermark_path",  # 水印图像路径
        output_path="watermarked.png"  # 输出图像路径
    )

    extracted_img = extract_watermark_rg(
        watermarked_path="watermarked.png",
        watermark_path="your_watermark_path",
        output_path="extracted_watermark_rg.png"
    )


