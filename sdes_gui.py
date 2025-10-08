from sdes import S_DES
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import random

class S_DES_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("S-DES加密解密工具")
        self.root.geometry("800x600")
        self.root.resizable(True, True)

        # 创建S-DES实例
        self.sdes = S_DES()

        # 创建标签页
        self.tab_control = ttk.Notebook(root)

        # 基本加解密标签页
        self.tab_basic = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_basic, text="基本加解密")

        # ASCII加解密标签页
        self.tab_ascii = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_ascii, text="ASCII加解密")

        # 暴力破解标签页
        self.tab_brute = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_brute, text="暴力破解")

        # 分析标签页
        self.tab_analysis = ttk.Frame(self.tab_control)
        self.tab_control.add(self.tab_analysis, text="密钥分析")

        self.tab_control.pack(expand=1, fill="both")

        # 初始化各个标签页
        self.init_basic_tab()
        self.init_ascii_tab()
        self.init_brute_tab()
        self.init_analysis_tab()

        # 状态变量
        self.brute_force_running = False

    def init_basic_tab(self):
        """初始化基本加解密标签页"""
        # 创建输入框架
        input_frame = ttk.LabelFrame(self.tab_basic, text="输入")
        input_frame.pack(fill="x", padx=10, pady=5)

        # 明文输入
        ttk.Label(input_frame, text="8位明文:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.plaintext_entry = ttk.Entry(input_frame, width=10)
        self.plaintext_entry.grid(row=0, column=1, padx=5, pady=5)
        self.plaintext_entry.insert(0, "00000000")

        # 密钥输入
        ttk.Label(input_frame, text="10位密钥:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.key_entry = ttk.Entry(input_frame, width=12)
        self.key_entry.grid(row=1, column=1, padx=5, pady=5)
        self.key_entry.insert(0, "0000000000")

        # 密文输入（用于解密）
        ttk.Label(input_frame, text="8位密文:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.ciphertext_entry = ttk.Entry(input_frame, width=10)
        self.ciphertext_entry.grid(row=2, column=1, padx=5, pady=5)
        self.ciphertext_entry.insert(0, "00000000")

        # 按钮框架
        button_frame = ttk.Frame(self.tab_basic)
        button_frame.pack(fill="x", padx=10, pady=5)

        # 加密按钮
        self.encrypt_btn = ttk.Button(button_frame, text="加密", command=self.perform_encrypt)
        self.encrypt_btn.pack(side="left", padx=5)

        # 解密按钮
        self.decrypt_btn = ttk.Button(button_frame, text="解密", command=self.perform_decrypt)
        self.decrypt_btn.pack(side="left", padx=5)

        # 随机生成按钮
        self.random_btn = ttk.Button(button_frame, text="随机生成", command=self.generate_random)
        self.random_btn.pack(side="left", padx=5)

        # 结果框架
        result_frame = ttk.LabelFrame(self.tab_basic, text="结果")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # 加密结果
        ttk.Label(result_frame, text="加密结果:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.encrypt_result = ttk.Entry(result_frame, width=10, state="readonly")
        self.encrypt_result.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # 解密结果
        ttk.Label(result_frame, text="解密结果:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.decrypt_result = ttk.Entry(result_frame, width=10, state="readonly")
        self.decrypt_result.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # 状态框
        ttk.Label(result_frame, text="状态:").grid(row=2, column=0, padx=5, pady=5, sticky="nw")
        self.status_text = scrolledtext.ScrolledText(result_frame, height=5, width=50)
        self.status_text.grid(row=2, column=1, padx=5, pady=5, sticky="nsew")
        self.status_text.insert(tk.END, "就绪")
        self.status_text.config(state="disabled")

        # 配置网格权重，使文本框可以扩展
        result_frame.grid_rowconfigure(2, weight=1)
        result_frame.grid_columnconfigure(1, weight=1)

    def init_ascii_tab(self):
        """初始化ASCII加解密标签页"""
        # 输入框架
        input_frame = ttk.LabelFrame(self.tab_ascii, text="输入")
        input_frame.pack(fill="x", padx=10, pady=5)

        # 密钥输入
        ttk.Label(input_frame, text="10位密钥:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.ascii_key_entry = ttk.Entry(input_frame, width=12)
        self.ascii_key_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ascii_key_entry.insert(0, "0000000000")

        # 明文输入
        ttk.Label(input_frame, text="明文:").grid(row=1, column=0, padx=5, pady=5, sticky="nw")
        self.ascii_plaintext = scrolledtext.ScrolledText(input_frame, height=5, width=50)
        self.ascii_plaintext.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        self.ascii_plaintext.insert(tk.END, "Hello, S-DES!")

        # 密文输入
        ttk.Label(input_frame, text="密文:").grid(row=2, column=0, padx=5, pady=5, sticky="nw")
        self.ascii_ciphertext = scrolledtext.ScrolledText(input_frame, height=5, width=50)
        self.ascii_ciphertext.grid(row=2, column=1, padx=5, pady=5, sticky="nsew")

        # 配置网格权重
        input_frame.grid_rowconfigure(1, weight=1)
        input_frame.grid_rowconfigure(2, weight=1)
        input_frame.grid_columnconfigure(1, weight=1)

        # 按钮框架
        button_frame = ttk.Frame(self.tab_ascii)
        button_frame.pack(fill="x", padx=10, pady=5)

        # 加密按钮
        self.ascii_encrypt_btn = ttk.Button(button_frame, text="加密", command=self.perform_ascii_encrypt)
        self.ascii_encrypt_btn.pack(side="left", padx=5)

        # 解密按钮
        self.ascii_decrypt_btn = ttk.Button(button_frame, text="解密", command=self.perform_ascii_decrypt)
        self.ascii_decrypt_btn.pack(side="left", padx=5)

        # 结果框架
        result_frame = ttk.LabelFrame(self.tab_ascii, text="结果")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # 加密结果
        ttk.Label(result_frame, text="加密结果:").pack(anchor="w", padx=5, pady=2)
        self.ascii_encrypt_result = scrolledtext.ScrolledText(result_frame, height=5, width=70)
        self.ascii_encrypt_result.pack(fill="both", expand=True, padx=5, pady=2)
        self.ascii_encrypt_result.config(state="disabled")

        # 解密结果
        ttk.Label(result_frame, text="解密结果:").pack(anchor="w", padx=5, pady=2)
        self.ascii_decrypt_result = scrolledtext.ScrolledText(result_frame, height=5, width=70)
        self.ascii_decrypt_result.pack(fill="both", expand=True, padx=5, pady=2)
        self.ascii_decrypt_result.config(state="disabled")

    def init_brute_tab(self):
        """初始化暴力破解标签页"""
        # 输入框架
        input_frame = ttk.LabelFrame(self.tab_brute, text="明密文对")
        input_frame.pack(fill="x", padx=10, pady=5)

        # 明文输入
        ttk.Label(input_frame, text="8位明文:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.brute_plaintext = ttk.Entry(input_frame, width=10)
        self.brute_plaintext.grid(row=0, column=1, padx=5, pady=5)
        self.brute_plaintext.insert(0, "00000000")

        # 密文输入
        ttk.Label(input_frame, text="8位密文:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.brute_ciphertext = ttk.Entry(input_frame, width=10)
        self.brute_ciphertext.grid(row=1, column=1, padx=5, pady=5)
        self.brute_ciphertext.insert(0, "00000000")

        # 按钮框架
        button_frame = ttk.Frame(self.tab_brute)
        button_frame.pack(fill="x", padx=10, pady=5)

        # 开始破解按钮
        self.start_brute_btn = ttk.Button(button_frame, text="开始暴力破解", command=self.start_brute_force)
        self.start_brute_btn.pack(side="left", padx=5)

        # 停止破解按钮
        self.stop_brute_btn = ttk.Button(button_frame, text="停止", command=self.stop_brute_force, state="disabled")
        self.stop_brute_btn.pack(side="left", padx=5)

        # 进度框架
        progress_frame = ttk.LabelFrame(self.tab_brute, text="进度")
        progress_frame.pack(fill="x", padx=10, pady=5)

        # 进度条
        self.brute_progress = ttk.Progressbar(progress_frame, orient="horizontal", length=100, mode="determinate")
        self.brute_progress.pack(fill="x", padx=5, pady=5)

        # 进度标签
        self.progress_label = ttk.Label(progress_frame, text="0%")
        self.progress_label.pack(pady=2)

        # 结果框架
        result_frame = ttk.LabelFrame(self.tab_brute, text="结果")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # 破解时间
        ttk.Label(result_frame, text="破解时间:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.brute_time = ttk.Entry(result_frame, width=20, state="readonly")
        self.brute_time.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        # 找到的密钥
        ttk.Label(result_frame, text="找到的密钥:").grid(row=1, column=0, padx=5, pady=5, sticky="nw")
        self.found_keys = scrolledtext.ScrolledText(result_frame, height=10, width=50)
        self.found_keys.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
        self.found_keys.config(state="disabled")

        # 配置网格权重
        result_frame.grid_rowconfigure(1, weight=1)
        result_frame.grid_columnconfigure(1, weight=1)

    def init_analysis_tab(self):
        """初始化密钥分析标签页"""
        # 说明文本
        desc_frame = ttk.LabelFrame(self.tab_analysis, text="说明")
        desc_frame.pack(fill="x", padx=10, pady=5)

        desc_text = """本页面用于分析S-DES算法的密钥特性，特别是密钥碰撞现象。
        即不同的密钥可能对同一明文加密得到相同的密文。"""
        ttk.Label(desc_frame, text=desc_text, wraplength=700).pack(padx=5, pady=5, fill="x")

        # 按钮框架
        button_frame = ttk.Frame(self.tab_analysis)
        button_frame.pack(fill="x", padx=10, pady=5)

        # 分析按钮
        self.analyze_btn = ttk.Button(button_frame, text="分析随机明密文对的密钥", command=self.start_analysis)
        self.analyze_btn.pack(side="left", padx=5)

        # 进度框架
        progress_frame = ttk.LabelFrame(self.tab_analysis, text="进度")
        progress_frame.pack(fill="x", padx=10, pady=5)

        # 进度条
        self.analysis_progress = ttk.Progressbar(progress_frame, orient="horizontal", length=100, mode="determinate")
        self.analysis_progress.pack(fill="x", padx=5, pady=5)

        # 进度标签
        self.analysis_label = ttk.Label(progress_frame, text="准备就绪")
        self.analysis_label.pack(pady=2)

        # 结果框架
        result_frame = ttk.LabelFrame(self.tab_analysis, text="分析结果")
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # 明文和密文
        ttk.Label(result_frame, text="测试明文:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.test_plaintext = ttk.Entry(result_frame, width=10, state="readonly")
        self.test_plaintext.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        ttk.Label(result_frame, text="测试密文:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.test_ciphertext = ttk.Entry(result_frame, width=10, state="readonly")
        self.test_ciphertext.grid(row=1, column=1, padx=5, pady=5, sticky="w")

        # 密钥数量
        ttk.Label(result_frame, text="有效密钥数量:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.key_count = ttk.Entry(result_frame, width=10, state="readonly")
        self.key_count.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        # 分析时间
        ttk.Label(result_frame, text="分析时间:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
        self.analysis_time = ttk.Entry(result_frame, width=20, state="readonly")
        self.analysis_time.grid(row=3, column=1, padx=5, pady=5, sticky="w")

        # 密钥列表
        ttk.Label(result_frame, text="有效密钥列表:").grid(row=4, column=0, padx=5, pady=5, sticky="nw")
        self.analysis_keys = scrolledtext.ScrolledText(result_frame, height=10, width=50)
        self.analysis_keys.grid(row=4, column=1, padx=5, pady=5, sticky="nsew")
        self.analysis_keys.config(state="disabled")

        # 配置网格权重
        result_frame.grid_rowconfigure(4, weight=1)
        result_frame.grid_columnconfigure(1, weight=1)

    def update_status(self, message):
        """更新状态文本框"""
        self.status_text.config(state="normal")
        self.status_text.delete(1.0, tk.END)
        self.status_text.insert(tk.END, message)
        self.status_text.config(state="disabled")

    def validate_input(self, text, length, name):
        """验证输入是否为指定长度的二进制字符串"""
        if len(text) != length:
            messagebox.showerror("输入错误", f"{name}必须是{length}位!")
            return False
        for c in text:
            if c not in ['0', '1']:
                messagebox.showerror("输入错误", f"{name}只能包含0和1!")
                return False
        return True

    def perform_encrypt(self):
        """执行加密操作"""
        plaintext = self.plaintext_entry.get()
        key = self.key_entry.get()

        # 验证输入
        if not self.validate_input(plaintext, 8, "明文"):
            return
        if not self.validate_input(key, 10, "密钥"):
            return

        try:
            # 执行加密
            ciphertext = self.sdes.encrypt(plaintext, key)

            # 更新结果
            self.encrypt_result.config(state="normal")
            self.encrypt_result.delete(0, tk.END)
            self.encrypt_result.insert(0, ciphertext)
            self.encrypt_result.config(state="readonly")

            # 更新密文输入框，方便解密测试
            self.ciphertext_entry.delete(0, tk.END)
            self.ciphertext_entry.insert(0, ciphertext)

            self.update_status(f"加密成功: {plaintext} -> {ciphertext}")
        except Exception as e:
            self.update_status(f"加密失败: {str(e)}")

    def perform_decrypt(self):
        """执行解密操作"""
        ciphertext = self.ciphertext_entry.get()
        key = self.key_entry.get()

        # 验证输入
        if not self.validate_input(ciphertext, 8, "密文"):
            return
        if not self.validate_input(key, 10, "密钥"):
            return

        try:
            # 执行解密
            plaintext = self.sdes.decrypt(ciphertext, key)

            # 更新结果
            self.decrypt_result.config(state="normal")
            self.decrypt_result.delete(0, tk.END)
            self.decrypt_result.insert(0, plaintext)
            self.decrypt_result.config(state="readonly")

            self.update_status(f"解密成功: {ciphertext} -> {plaintext}")
        except Exception as e:
            self.update_status(f"解密失败: {str(e)}")

    def generate_random(self):
        """生成随机的明文和密钥"""
        # 生成8位随机明文
        plaintext = ''.join(str(random.randint(0, 1)) for _ in range(8))
        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, plaintext)

        # 生成10位随机密钥
        key = ''.join(str(random.randint(0, 1)) for _ in range(10))
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key)

        self.update_status("已生成随机明文和密钥")

    def perform_ascii_encrypt(self):
        """执行ASCII字符串加密"""
        plaintext = self.ascii_plaintext.get("1.0", tk.END).rstrip('\n')
        key = self.ascii_key_entry.get()

        # 验证密钥
        if not self.validate_input(key, 10, "密钥"):
            return

        try:
            # 执行加密
            ciphertext = self.sdes.encrypt_ascii(plaintext, key)

            # 更新结果
            self.ascii_encrypt_result.config(state="normal")
            self.ascii_encrypt_result.delete(1.0, tk.END)
            self.ascii_encrypt_result.insert(tk.END, ciphertext)
            self.ascii_encrypt_result.config(state="disabled")

            # 更新密文输入框
            self.ascii_ciphertext.delete(1.0, tk.END)
            self.ascii_ciphertext.insert(tk.END, ciphertext)
        except Exception as e:
            messagebox.showerror("加密失败", str(e))

    def perform_ascii_decrypt(self):
        """执行ASCII字符串解密"""
        ciphertext = self.ascii_ciphertext.get("1.0", tk.END).rstrip('\n')
        key = self.ascii_key_entry.get()

        # 验证密钥
        if not self.validate_input(key, 10, "密钥"):
            return

        try:
            # 执行解密
            plaintext = self.sdes.decrypt_ascii(ciphertext, key)

            # 更新结果
            self.ascii_decrypt_result.config(state="normal")
            self.ascii_decrypt_result.delete(1.0, tk.END)
            self.ascii_decrypt_result.insert(tk.END, plaintext)
            self.ascii_decrypt_result.config(state="disabled")
        except Exception as e:
            messagebox.showerror("解密失败", str(e))

    def update_brute_progress(self, progress):
        """更新暴力破解进度"""
        self.brute_progress["value"] = progress
        self.progress_label.config(text=f"{progress:.1f}%")
        self.root.update_idletasks()

    def brute_force_worker(self, plaintext, ciphertext):
        """暴力破解工作线程"""
        keys, time_elapsed = self.sdes.brute_force(plaintext, ciphertext, self.update_brute_progress)

        # 更新UI
        self.found_keys.config(state="normal")
        self.found_keys.delete(1.0, tk.END)
        for key in keys:
            self.found_keys.insert(tk.END, key + "\n")
        self.found_keys.config(state="disabled")

        # 更新时间
        self.brute_time.config(state="normal")
        self.brute_time.delete(0, tk.END)
        self.brute_time.insert(0, f"{time_elapsed:.4f}秒")
        self.brute_time.config(state="readonly")

        # 恢复按钮状态
        self.start_brute_btn.config(state="normal")
        self.stop_brute_btn.config(state="disabled")
        self.brute_force_running = False

        if len(keys) == 0:
            messagebox.showinfo("完成", "未找到匹配的密钥")
        else:
            messagebox.showinfo("完成", f"找到{len(keys)}个匹配的密钥，耗时{time_elapsed:.4f}秒")

    def start_brute_force(self):
        """开始暴力破解"""
        plaintext = self.brute_plaintext.get()
        ciphertext = self.brute_ciphertext.get()

        # 验证输入
        if not self.validate_input(plaintext, 8, "明文"):
            return
        if not self.validate_input(ciphertext, 8, "密文"):
            return

        # 重置进度
        self.brute_progress["value"] = 0
        self.progress_label.config(text="0%")

        # 清空结果
        self.found_keys.config(state="normal")
        self.found_keys.delete(1.0, tk.END)
        self.found_keys.config(state="disabled")

        self.brute_time.config(state="normal")
        self.brute_time.delete(0, tk.END)
        self.brute_time.config(state="readonly")

        # 禁用开始按钮，启用停止按钮
        self.start_brute_btn.config(state="disabled")
        self.stop_brute_btn.config(state="normal")
        self.brute_force_running = True

        # 在新线程中执行暴力破解
        threading.Thread(target=self.brute_force_worker, args=(plaintext, ciphertext), daemon=True).start()

    def stop_brute_force(self):
        """停止暴力破解"""
        self.brute_force_running = False
        self.start_brute_btn.config(state="normal")
        self.stop_brute_btn.config(state="disabled")
        self.update_brute_progress(0)
        self.progress_label.config(text="已停止")

    def update_analysis_progress(self, progress):
        """更新分析进度"""
        self.analysis_progress["value"] = progress
        self.analysis_label.config(text=f"分析中: {progress:.1f}%")
        self.root.update_idletasks()

    def analysis_worker(self):
        """密钥分析工作线程"""
        # 生成随机明文
        plaintext = ''.join(str(random.randint(0, 1)) for _ in range(8))

        # 随机选择一个密钥加密生成密文
        key = ''.join(str(random.randint(0, 1)) for _ in range(10))
        ciphertext = self.sdes.encrypt(plaintext, key)

        # 查找所有能将该明文加密为该密文的密钥
        keys, time_elapsed = self.sdes.brute_force(plaintext, ciphertext, self.update_analysis_progress)

        # 更新UI
        self.test_plaintext.config(state="normal")
        self.test_plaintext.delete(0, tk.END)
        self.test_plaintext.insert(0, plaintext)
        self.test_plaintext.config(state="readonly")

        self.test_ciphertext.config(state="normal")
        self.test_ciphertext.delete(0, tk.END)
        self.test_ciphertext.insert(0, ciphertext)
        self.test_ciphertext.config(state="readonly")

        self.key_count.config(state="normal")
        self.key_count.delete(0, tk.END)
        self.key_count.insert(0, str(len(keys)))
        self.key_count.config(state="readonly")

        self.analysis_time.config(state="normal")
        self.analysis_time.delete(0, tk.END)
        self.analysis_time.insert(0, f"{time_elapsed:.4f}秒")
        self.analysis_time.config(state="readonly")

        self.analysis_keys.config(state="normal")
        self.analysis_keys.delete(1.0, tk.END)
        for k in keys:
            self.analysis_keys.insert(tk.END, k + "\n")
        self.analysis_keys.config(state="disabled")

        # 恢复按钮状态
        self.analyze_btn.config(state="normal")
        self.analysis_label.config(text="分析完成")

        # 显示结论
        if len(keys) > 1:
            messagebox.showinfo("分析结果",
                                f"对于明文 {plaintext} 和密文 {ciphertext}，找到 {len(keys)} 个有效密钥，说明存在密钥碰撞现象。")
        else:
            messagebox.showinfo("分析结果", f"对于明文 {plaintext} 和密文 {ciphertext}，只找到 {len(keys)} 个有效密钥。")

    def start_analysis(self):
        """开始密钥分析"""
        # 重置进度
        self.analysis_progress["value"] = 0
        self.analysis_label.config(text="分析中: 0%")

        # 禁用分析按钮
        self.analyze_btn.config(state="disabled")

        # 在新线程中执行分析
        threading.Thread(target=self.analysis_worker, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = S_DES_GUI(root)
    root.mainloop()
