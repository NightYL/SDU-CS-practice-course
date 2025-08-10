from PIL import Image, ImageEnhance
import numpy as np
import cv2
from skimage.metrics import structural_similarity as ssim
import os
import matplotlib.pyplot as plt
from LSB import embed_watermark_rg, extract_watermark_rg


class LSBRobustnessTest:
    def __init__(self):
        self.results = {}

    def calculate_psnr(self, img1, img2):
        """计算PSNR值"""
        mse = np.mean((img1.astype(float) - img2.astype(float)) ** 2)
        if mse == 0:
            return float('inf')
        return 20 * np.log10(255.0 / np.sqrt(mse))

    def calculate_nc(self, original_watermark, extracted_watermark):
        """计算归一化相关系数(Normalized Correlation)"""
        original = np.array(original_watermark).astype(float)
        extracted = np.array(extracted_watermark).astype(float)

        # 确保两个图像大小相同
        if original.shape != extracted.shape:
            min_h = min(original.shape[0], extracted.shape[0])
            min_w = min(original.shape[1], extracted.shape[1])
            original = original[:min_h, :min_w]
            extracted = extracted[:min_h, :min_w]

        # 计算NC
        numerator = np.sum(original * extracted)
        denominator = np.sqrt(np.sum(original ** 2) * np.sum(extracted ** 2))

        if denominator == 0:
            return 0
        return numerator / denominator

    def flip_attack(self, image_path, output_path, flip_mode='horizontal'):
        """翻转攻击"""
        img = Image.open(image_path)

        if flip_mode == 'horizontal':
            flipped = img.transpose(Image.FLIP_LEFT_RIGHT)
        elif flip_mode == 'vertical':
            flipped = img.transpose(Image.FLIP_TOP_BOTTOM)
        elif flip_mode == 'both':
            flipped = img.transpose(Image.FLIP_LEFT_RIGHT).transpose(Image.FLIP_TOP_BOTTOM)

        flipped.save(output_path)
        return flipped

    def translation_attack(self, image_path, output_path, dx=10, dy=10):
        """平移攻击"""
        img = cv2.imread(image_path)
        h, w = img.shape[:2]

        # 创建平移变换矩阵
        translation_matrix = np.float32([[1, 0, dx], [0, 1, dy]])

        # 应用平移变换
        translated = cv2.warpAffine(img, translation_matrix, (w, h))

        cv2.imwrite(output_path, translated)
        return Image.open(output_path)

    def rotation_attack(self, image_path, output_path, angle=15):
        """旋转攻击"""
        img = cv2.imread(image_path)
        h, w = img.shape[:2]
        center = (w // 2, h // 2)

        # 创建旋转变换矩阵
        rotation_matrix = cv2.getRotationMatrix2D(center, angle, 1.0)

        # 应用旋转变换
        rotated = cv2.warpAffine(img, rotation_matrix, (w, h))

        cv2.imwrite(output_path, rotated)
        return Image.open(output_path)

    def crop_attack(self, image_path, output_path, crop_ratio=0.8):
        """截取攻击"""
        img = Image.open(image_path)
        w, h = img.size

        # 计算裁剪区域
        new_w = int(w * crop_ratio)
        new_h = int(h * crop_ratio)
        left = (w - new_w) // 2
        top = (h - new_h) // 2
        right = left + new_w
        bottom = top + new_h

        # 裁剪图像
        cropped = img.crop((left, top, right, bottom))
        # 调整回原始尺寸
        cropped_resized = cropped.resize((w, h), Image.Resampling.LANCZOS)

        cropped_resized.save(output_path)
        return cropped_resized

    def contrast_attack(self, image_path, output_path, factor=1.5):
        """对比度调整攻击"""
        img = Image.open(image_path)
        enhancer = ImageEnhance.Contrast(img)
        enhanced = enhancer.enhance(factor)
        enhanced.save(output_path)
        return enhanced

    def brightness_attack(self, image_path, output_path, factor=1.3):
        """亮度调整攻击"""
        img = Image.open(image_path)
        enhancer = ImageEnhance.Brightness(img)
        enhanced = enhancer.enhance(factor)
        enhanced.save(output_path)
        return enhanced

    def gaussian_noise_attack(self, image_path, output_path, noise_level=10):
        """高斯噪声攻击"""
        img = cv2.imread(image_path)

        # 生成高斯噪声
        noise = np.random.normal(0, noise_level, img.shape).astype(np.uint8)

        # 添加噪声
        noisy_img = cv2.add(img, noise)

        cv2.imwrite(output_path, noisy_img)
        return Image.open(output_path)

    def salt_pepper_noise_attack(self, image_path, output_path, noise_ratio=0.05):
        """椒盐噪声攻击"""
        img = cv2.imread(image_path)

        # 添加椒盐噪声
        h, w, c = img.shape
        noise_mask = np.random.random((h, w)) < noise_ratio

        # 随机设置为黑色或白色
        for i in range(h):
            for j in range(w):
                if noise_mask[i, j]:
                    if np.random.random() < 0.5:
                        img[i, j] = [0, 0, 0]  # 黑色
                    else:
                        img[i, j] = [255, 255, 255]  # 白色

        cv2.imwrite(output_path, img)
        return Image.open(output_path)

    def jpeg_compression_attack(self, image_path, output_path, quality=50):
        """JPEG压缩攻击"""
        img = Image.open(image_path)
        img.save(output_path, 'JPEG', quality=quality)
        return Image.open(output_path)

    def scaling_attack(self, image_path, output_path, scale_factor=0.5):
        """缩放攻击"""
        img = Image.open(image_path)
        original_size = img.size

        # 缩小然后放大回原始尺寸
        new_size = (int(original_size[0] * scale_factor), int(original_size[1] * scale_factor))
        scaled_down = img.resize(new_size, Image.Resampling.LANCZOS)
        scaled_back = scaled_down.resize(original_size, Image.Resampling.LANCZOS)

        scaled_back.save(output_path)
        return scaled_back

    def run_comprehensive_test(self, original_image_path, watermark_path, output_dir="robustness_test"):
        """运行综合鲁棒性测试"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # 首先嵌入水印
        watermarked_path = os.path.join(output_dir, "watermarked.png")
        embed_watermark_rg(original_image_path, watermark_path, watermarked_path)

        # 加载原始水印用于比较
        original_watermark = Image.open(watermark_path).convert('L')

        # 定义测试攻击
        attacks = {
            "水平翻转": lambda: self.flip_attack(watermarked_path,
                                                 os.path.join(output_dir, "flipped_h.png"), 'horizontal'),
            "垂直翻转": lambda: self.flip_attack(watermarked_path,
                                                 os.path.join(output_dir, "flipped_v.png"), 'vertical'),
            "平移(10,10)": lambda: self.translation_attack(watermarked_path,
                                                           os.path.join(output_dir, "translated.png"), 10, 10),
            "旋转15度": lambda: self.rotation_attack(watermarked_path,
                                                     os.path.join(output_dir, "rotated.png"), 15),
            "截取80%": lambda: self.crop_attack(watermarked_path,
                                                os.path.join(output_dir, "cropped.png"), 0.8),
            "对比度+50%": lambda: self.contrast_attack(watermarked_path,
                                                       os.path.join(output_dir, "contrast.png"), 1.5),
            "亮度+30%": lambda: self.brightness_attack(watermarked_path,
                                                       os.path.join(output_dir, "brightness.png"), 1.3),
            "高斯噪声": lambda: self.gaussian_noise_attack(watermarked_path,
                                                           os.path.join(output_dir, "gaussian_noise.png"), 10),
            "椒盐噪声": lambda: self.salt_pepper_noise_attack(watermarked_path,
                                                              os.path.join(output_dir, "salt_pepper.png"), 0.05),
            "JPEG压缩(Q=50)": lambda: self.jpeg_compression_attack(watermarked_path,
                                                                   os.path.join(output_dir, "jpeg_compressed.png"), 50),
            "缩放50%": lambda: self.scaling_attack(watermarked_path,
                                                   os.path.join(output_dir, "scaled.png"), 0.5),
        }

        print("开始LSB水印鲁棒性测试...")
        print("=" * 60)

        self.results = {}

        for attack_name, attack_func in attacks.items():
            try:
                # 执行攻击
                print(f"正在测试: {attack_name}")
                attack_func()

                # 从攻击后的图像提取水印
                attacked_path = [path for path in
                                 [os.path.join(output_dir,
                                               f"{attack_name.split('(')[0].replace(' ', '_').lower()}.png"),
                                  os.path.join(output_dir, "flipped_h.png"),
                                  os.path.join(output_dir, "flipped_v.png"),
                                  os.path.join(output_dir, "translated.png"),
                                  os.path.join(output_dir, "rotated.png"),
                                  os.path.join(output_dir, "cropped.png"),
                                  os.path.join(output_dir, "contrast.png"),
                                  os.path.join(output_dir, "brightness.png"),
                                  os.path.join(output_dir, "gaussian_noise.png"),
                                  os.path.join(output_dir, "salt_pepper.png"),
                                  os.path.join(output_dir, "jpeg_compressed.png"),
                                  os.path.join(output_dir, "scaled.png")]
                                 if os.path.exists(path)]

                if attack_name == "水平翻转":
                    attacked_image_path = os.path.join(output_dir, "flipped_h.png")
                elif attack_name == "垂直翻转":
                    attacked_image_path = os.path.join(output_dir, "flipped_v.png")
                elif attack_name == "平移(10,10)":
                    attacked_image_path = os.path.join(output_dir, "translated.png")
                elif attack_name == "旋转15度":
                    attacked_image_path = os.path.join(output_dir, "rotated.png")
                elif attack_name == "截取80%":
                    attacked_image_path = os.path.join(output_dir, "cropped.png")
                elif attack_name == "对比度+50%":
                    attacked_image_path = os.path.join(output_dir, "contrast.png")
                elif attack_name == "亮度+30%":
                    attacked_image_path = os.path.join(output_dir, "brightness.png")
                elif attack_name == "高斯噪声":
                    attacked_image_path = os.path.join(output_dir, "gaussian_noise.png")
                elif attack_name == "椒盐噪声":
                    attacked_image_path = os.path.join(output_dir, "salt_pepper.png")
                elif attack_name == "JPEG压缩(Q=50)":
                    attacked_image_path = os.path.join(output_dir, "jpeg_compressed.png")
                elif attack_name == "缩放50%":
                    attacked_image_path = os.path.join(output_dir, "scaled.png")

                extracted_watermark_path = os.path.join(output_dir,
                                                        f"extracted_{attack_name.replace(' ', '_').replace('(', '_').replace(')', '').replace('%', 'percent').replace('+', 'plus').replace('=', 'eq')}.png")

                try:
                    extract_watermark_rg(attacked_image_path, watermark_path, extracted_watermark_path)
                    extracted_watermark = Image.open(extracted_watermark_path).convert('L')

                    # 计算评估指标
                    nc = self.calculate_nc(original_watermark, extracted_watermark)

                    # 计算PSNR和SSIM
                    orig_array = np.array(original_watermark)
                    ext_array = np.array(extracted_watermark)

                    # 确保尺寸一致
                    min_h = min(orig_array.shape[0], ext_array.shape[0])
                    min_w = min(orig_array.shape[1], ext_array.shape[1])
                    orig_array = orig_array[:min_h, :min_w]
                    ext_array = ext_array[:min_h, :min_w]

                    psnr = self.calculate_psnr(orig_array, ext_array)
                    ssim_value = ssim(orig_array, ext_array)

                    self.results[attack_name] = {
                        'NC': nc,
                        'PSNR': psnr,
                        'SSIM': ssim_value,
                        'Status': '成功' if nc > 0.5 else '失败'
                    }

                    print(
                        f"  NC: {nc:.4f}, PSNR: {psnr:.2f}dB, SSIM: {ssim_value:.4f}, 状态: {self.results[attack_name]['Status']}")

                except Exception as e:
                    self.results[attack_name] = {
                        'NC': 0,
                        'PSNR': 0,
                        'SSIM': 0,
                        'Status': f'提取失败: {str(e)}'
                    }
                    print(f"  提取水印失败: {str(e)}")

            except Exception as e:
                print(f"  攻击执行失败: {str(e)}")
                self.results[attack_name] = {
                    'NC': 0,
                    'PSNR': 0,
                    'SSIM': 0,
                    'Status': f'攻击失败: {str(e)}'
                }

        # 生成测试报告
        self.generate_report(output_dir)

        return self.results

    def generate_report(self, output_dir):
        """生成测试报告"""
        print("\n" + "=" * 60)
        print("LSB水印鲁棒性测试报告")
        print("=" * 60)

        # 统计成功率
        total_tests = len(self.results)
        successful_tests = sum(1 for result in self.results.values()
                               if isinstance(result['Status'], str) and result['Status'] == '成功')
        success_rate = successful_tests / total_tests * 100

        print(f"总测试数量: {total_tests}")
        print(f"成功通过: {successful_tests}")
        print(f"成功率: {success_rate:.1f}%")
        print("\n详细结果:")
        print("-" * 60)
        print(f"{'攻击类型':<15} {'NC':<8} {'PSNR(dB)':<10} {'SSIM':<8} {'状态':<10}")
        print("-" * 60)

        for attack_name, metrics in self.results.items():
            nc = metrics['NC']
            psnr = metrics['PSNR']
            ssim_val = metrics['SSIM']
            status = metrics['Status']

            print(f"{attack_name:<15} {nc:<8.4f} {psnr:<10.2f} {ssim_val:<8.4f} {status:<10}")

        # 保存报告到文件
        report_path = os.path.join(output_dir, "robustness_report.txt")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("LSB水印鲁棒性测试报告\n")
            f.write("=" * 60 + "\n")
            f.write(f"总测试数量: {total_tests}\n")
            f.write(f"成功通过: {successful_tests}\n")
            f.write(f"成功率: {success_rate:.1f}%\n\n")
            f.write("详细结果:\n")
            f.write("-" * 60 + "\n")
            f.write(f"{'攻击类型':<15} {'NC':<8} {'PSNR(dB)':<10} {'SSIM':<8} {'状态':<10}\n")
            f.write("-" * 60 + "\n")

            for attack_name, metrics in self.results.items():
                nc = metrics['NC']
                psnr = metrics['PSNR']
                ssim_val = metrics['SSIM']
                status = metrics['Status']
                f.write(f"{attack_name:<15} {nc:<8.4f} {psnr:<10.2f} {ssim_val:<8.4f} {status:<10}\n")

        print(f"\n测试报告已保存至: {report_path}")

        # 创建可视化图表
        self.create_visualization(output_dir)

    def create_visualization(self, output_dir):
        """创建可视化图表"""
        try:
            # 提取数据
            attack_names = list(self.results.keys())
            nc_values = [self.results[name]['NC'] for name in attack_names]
            psnr_values = [self.results[name]['PSNR'] if self.results[name]['PSNR'] != float('inf')
                           else 100 for name in attack_names]
            ssim_values = [self.results[name]['SSIM'] for name in attack_names]

            # 创建图表
            fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(12, 15))

            # NC值图表
            bars1 = ax1.bar(range(len(attack_names)), nc_values, color='skyblue', alpha=0.7)
            ax1.set_title('归一化相关系数 (NC)', fontsize=14, fontweight='bold')
            ax1.set_ylabel('NC值')
            ax1.set_xticks(range(len(attack_names)))
            ax1.set_xticklabels(attack_names, rotation=45, ha='right')
            ax1.axhline(y=0.5, color='red', linestyle='--', alpha=0.7, label='阈值 (0.5)')
            ax1.legend()
            ax1.grid(True, alpha=0.3)

            # 添加数值标签
            for i, bar in enumerate(bars1):
                height = bar.get_height()
                ax1.text(bar.get_x() + bar.get_width() / 2., height + 0.01,
                         f'{nc_values[i]:.3f}', ha='center', va='bottom', fontsize=8)

            # PSNR值图表
            bars2 = ax2.bar(range(len(attack_names)), psnr_values, color='lightgreen', alpha=0.7)
            ax2.set_title('峰值信噪比 (PSNR)', fontsize=14, fontweight='bold')
            ax2.set_ylabel('PSNR (dB)')
            ax2.set_xticks(range(len(attack_names)))
            ax2.set_xticklabels(attack_names, rotation=45, ha='right')
            ax2.grid(True, alpha=0.3)

            # 添加数值标签
            for i, bar in enumerate(bars2):
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width() / 2., height + 1,
                         f'{psnr_values[i]:.1f}', ha='center', va='bottom', fontsize=8)

            # SSIM值图表
            bars3 = ax3.bar(range(len(attack_names)), ssim_values, color='lightcoral', alpha=0.7)
            ax3.set_title('结构相似性指数 (SSIM)', fontsize=14, fontweight='bold')
            ax3.set_ylabel('SSIM值')
            ax3.set_xticks(range(len(attack_names)))
            ax3.set_xticklabels(attack_names, rotation=45, ha='right')
            ax3.grid(True, alpha=0.3)

            # 添加数值标签
            for i, bar in enumerate(bars3):
                height = bar.get_height()
                ax3.text(bar.get_x() + bar.get_width() / 2., height + 0.01,
                         f'{ssim_values[i]:.3f}', ha='center', va='bottom', fontsize=8)

            plt.tight_layout()
            chart_path = os.path.join(output_dir, "robustness_chart.png")
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            print(f"可视化图表已保存至: {chart_path}")

        except Exception as e:
            print(f"生成可视化图表时出错: {str(e)}")


# 使用示例
if __name__ == "__main__":
    # 创建测试实例
    tester = LSBRobustnessTest()

    try:
        results = tester.run_comprehensive_test(
            original_image_path="./source/Pic.png",
            watermark_path="./source/watermark.png",
            output_dir="robustness_test"
        )

        print("\n测试完成！结果已保存在 'robustness_test' 文件夹中。")

    except FileNotFoundError as e:
        print(f"文件未找到错误: {e}")
        print("请确保以下文件存在:")
        print("- ./source/Pic.png (原始图像)")
        print("- ./source/watermark.png (水印图像)")
    except Exception as e:

        print(f"测试过程中出现错误: {e}")
