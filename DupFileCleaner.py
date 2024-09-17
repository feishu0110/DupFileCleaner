import os
import hashlib
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, StringVar, BooleanVar, IntVar
from tkinter.scrolledtext import ScrolledText
from tkinter import font as tkfont
from multiprocessing import Pool, Manager, cpu_count, Queue
from queue import Empty
from collections import defaultdict
import threading
from threading import Thread
import time

class FileMerger:
    def __init__(self, root):
        self.root = root
        self.root.title("文件去重工具")
        self.root.geometry("1000x700")
        self.root.configure(bg="#f0f0f0")

        # 设置窗口图标
        # self.root.iconbitmap('文件去重工具.ico')  # 使用当前文件夹中的图标文件

        # 自定义样式
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        # 按钮样式
        self.style.configure("TButton", 
                             padding=10, 
                             relief="flat", 
                             background="#4CAF50", 
                             foreground="white", 
                             font=("Helvetica", 11, "bold"),
                             borderwidth=0)
        self.style.map("TButton", 
                       background=[("active", "#45a049"), ("pressed", "#3d8b40")],
                       relief=[("pressed", "flat"), ("!pressed", "flat")])
        
        # 进度条样式
        self.style.configure("TProgressbar", 
                             thickness=25, 
                             troughcolor="#E0E0E0", 
                             background="#4CAF50")

        # 标签样式
        self.style.configure("TLabel", 
                             background="#f0f0f0", 
                             font=("Helvetica", 11))

        # 输入框样式
        self.style.configure("TEntry", 
                             font=("Helvetica", 11), 
                             padding=5)

        main_frame = ttk.Frame(root, padding="20 20 20 20", style="TFrame")
        main_frame.pack(fill="both", expand=True)

        # 目录选择
        dir_frame = ttk.Frame(main_frame)
        dir_frame.pack(fill="x", pady=(0, 20))

        self.directory_var = tk.StringVar()
        self.directory_entry = ttk.Entry(dir_frame, textvariable=self.directory_var, width=70)
        self.directory_entry.pack(side="left", expand=True, fill="x", padx=(0, 10))

        self.select_button = ttk.Button(dir_frame, text="选择目录", command=self.select_directory, width=15)
        self.select_button.pack(side="right")

        # 文件类型选择
        file_type_frame = ttk.Frame(main_frame)
        file_type_frame.pack(fill="x", pady=(0, 20))

        self.file_type_var = IntVar(value=0)  # 用于单选按钮的变量

        self.video_var = BooleanVar()
        self.image_var = BooleanVar()
        self.office_var = BooleanVar()

        self.video_check = ttk.Checkbutton(file_type_frame, text="视频", variable=self.video_var, command=self.update_checkboxes)
        self.video_check.pack(side="left", padx=(0, 10))

        self.image_check = ttk.Checkbutton(file_type_frame, text="图片", variable=self.image_var, command=self.update_checkboxes)
        self.image_check.pack(side="left", padx=(0, 10))

        self.office_check = ttk.Checkbutton(file_type_frame, text="办公文件", variable=self.office_var, command=self.update_checkboxes)
        self.office_check.pack(side="left", padx=(0, 10))

        self.all_check = ttk.Radiobutton(file_type_frame, text="所有文件", variable=self.file_type_var, value=0, command=self.update_radiobutton)
        self.all_check.pack(side="left", padx=(0, 10))

        # 操作按钮
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=(0, 20))

        self.find_duplicates_button = ttk.Button(button_frame, text="查找重复文件", command=self.start_scan, width=20)
        self.find_duplicates_button.pack(side="left", padx=(0, 10))

        self.merge_button = ttk.Button(button_frame, text="合并重复文件", command=self.merge_files, width=20)
        self.merge_button.pack(side="left", padx=(0, 10))

        self.cancel_button = ttk.Button(button_frame, text="取消", command=self.cancel, width=15)
        self.cancel_button.pack(side="left")

        self.export_log_button = ttk.Button(button_frame, text="导出日志", command=self.export_log, width=15)
        self.export_log_button.pack(side="left", padx=(10, 0))

        # 进度条和标签
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill="x", pady=(0, 10))

        self.progress = ttk.Progressbar(progress_frame, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(side="left", expand=True, fill="x", padx=(0, 10))

        self.progress_label = ttk.Label(progress_frame, text="")
        self.progress_label.pack(side="right")

        self.current_folder_label = ttk.Label(main_frame, text="", wraplength=950)
        self.current_folder_label.pack(pady=5, fill="x")

        # 结果文本框
        result_frame = ttk.Frame(main_frame)
        result_frame.pack(fill="both", expand=True)

        self.result_text = ScrolledText(result_frame, wrap=tk.WORD, font=("Helvetica", 11))
        self.result_text.pack(fill="both", expand=True)

        # 初始化多进程变量
        self.manager = Manager()
        self.file_hashes = self.manager.dict()
        self.cancel_flag = self.manager.Value('i', 0)
        self.directory = ""
        self.total_files = self.manager.Value('i', 0)
        self.scanned_files = self.manager.Value('i', 0)
        self.progress_queue = self.manager.Queue()

    def select_directory(self):
        self.directory = filedialog.askdirectory()
        if self.directory:
            self.directory_var.set(self.directory)

    def start_scan(self):
        if not self.directory:
            messagebox.showinfo("提示", "请先选择文件目录")
            return
        self.file_hashes.clear()
        self.cancel_flag.value = 0
        self.progress["value"] = 0
        self.scanned_files.value = 0
        self.total_files.value = 0
        self.result_text.delete('1.0', 'end')
        
        self.find_duplicates_button.config(state="disabled")
        self.merge_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        
        Thread(target=self.scan_files, daemon=True).start()
        self.update_progress()

    def scan_files(self):
        # 支持的文件扩展名
        video_extensions = {'.mp4', '.avi', '.mov', '.mkv', '.flv', '.wmv'}
        image_extensions = {'.heic', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff'}
        office_extensions = {'.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf'}
        
        supported_extensions = set()
        if self.file_type_var.get() == 0:
            supported_extensions = None  # 如果选择了所有文件，则不限制扩展名
        else:
            if self.video_var.get():
                supported_extensions.update(video_extensions)
            if self.image_var.get():
                supported_extensions.update(image_extensions)
            if self.office_var.get():
                supported_extensions.update(office_extensions)
        
        with Pool(processes=cpu_count()) as pool:
            for root, _, files in os.walk(self.directory):
                if self.cancel_flag.value:
                    break
                current_folder = os.path.relpath(root, self.directory)
                file_paths = [(os.path.join(root, file), current_folder) for file in files if self.is_supported_file(file, supported_extensions)]
                self.total_files.value += len(file_paths)
                self.progress_queue.put(("update_total", self.total_files.value))
                
                for result in pool.imap_unordered(process_file, file_paths, chunksize=100):
                    if self.cancel_flag.value:
                        pool.terminate()
                        break
                    if result:
                        self.file_hashes[result[0]] = result[1]
                        self.scanned_files.value += 1
                        self.progress_queue.put(("scan", (self.scanned_files.value, result[2])))

        self.progress_queue.put(("scan_complete", None))

    def is_supported_file(self, file, supported_extensions):
        if supported_extensions is None:
            return True  # 如果选择了所有文件，则支持所有文件
        file_extension = os.path.splitext(file)[1].lower()
        return file_extension in supported_extensions

    def update_progress(self):
        try:
            while True:
                action, value = self.progress_queue.get_nowait()
                if action == "update_total":
                    self.progress["maximum"] = max(value, 1)
                elif action == "scan":
                    scanned_files, current_folder = value
                    self.progress["value"] = scanned_files
                    progress_text = f"已扫描: {scanned_files}/{self.total_files.value} 文件"
                    self.progress_label.config(text=progress_text)
                    self.current_folder_label.config(text=f"当前文件夹: {current_folder}")
                elif action == "scan_complete":
                    self.find_duplicates()
                    return
                elif action == "merge":
                    self.progress["value"] = value
                    progress_text = f"已合并: {value}/{self.progress['maximum']} 组"
                    self.progress_label.config(text=progress_text)
                elif action == "merge_complete":
                    self.progress["value"] = self.progress["maximum"]  # 确保进度条满格
                    self.reset_ui()
                    messagebox.showinfo("合并完成", f"已合并 {value} 组重复文件")
                    return
        except Empty:
            pass
        
        self.root.after(100, self.update_progress)

    def find_duplicates(self):
        hash_to_files = defaultdict(list)
        for file_path, file_hash in self.file_hashes.items():
            hash_to_files[file_hash].append(file_path)
        
        duplicates = {h: files for h, files in hash_to_files.items() if len(files) > 1}
        
        if duplicates:
            self.result_text.delete('1.0', 'end')
            self.result_text.insert('end', f"共发现 {len(duplicates)} 组重复文件：\n\n")
            for files in duplicates.values():
                self.result_text.insert('end', f"重复文件 ({len(files)} 个副本):\n")
                for file in files:
                    self.result_text.insert('end', f"  {file}\n")
                self.result_text.insert('end', "\n")
        else:
            self.result_text.delete('1.0', 'end')
            self.result_text.insert('end', "未找到重复文件")

        self.reset_ui()

    def merge_files(self):
        if not self.file_hashes:
            messagebox.showinfo("提示", "请先扫描文件并查找重复")
            return
        
        hash_to_files = defaultdict(list)
        for file_path, file_hash in self.file_hashes.items():
            hash_to_files[file_hash].append(file_path)
        
        duplicates = {h: files for h, files in hash_to_files.items() if len(files) > 1}
        
        if not duplicates:
            messagebox.showinfo("无重复文件", "未找到重复文件")
            return
        
        if not messagebox.askyesno("确认合并", f"找到 {len(duplicates)} 组重复文件。是否继续合并？"):
            return
        
        merged_dir = os.path.join(self.directory, "merged_files")
        os.makedirs(merged_dir, exist_ok=True)
        
        self.progress["value"] = 0
        self.progress["maximum"] = len(duplicates)
        
        self.find_duplicates_button.config(state="disabled")
        self.merge_button.config(state="disabled")
        self.cancel_button.config(state="normal")
        
        Thread(target=self.merge_files_thread, args=(duplicates, merged_dir), daemon=True).start()
        self.update_progress()

    def merge_files_thread(self, duplicates, merged_dir):
        merged_count = 0
        with Pool(processes=cpu_count()) as pool:
            for result in pool.imap_unordered(merge_file_group, [(files, merged_dir) for files in duplicates.values()]):
                if self.cancel_flag.value:
                    pool.terminate()
                    break
                if result:
                    main_file, deleted_files, error = result
                    if error:
                        self.result_text.insert('end', f"合并文件组时出错: {main_file}, 错误信息: {error}\n")
                    else:
                        merged_count += 1
                        self.progress_queue.put(("merge", merged_count))
                        self.result_text.insert('end', f"合并组：\n  保留: {main_file}\n  删除: {', '.join(deleted_files)}\n\n")
        
        self.progress_queue.put(("merge_complete", merged_count))

    def reset_ui(self):
        self.find_duplicates_button.config(state="normal")
        self.merge_button.config(state="normal")
        self.cancel_button.config(state="disabled")
        self.progress_label.config(text="操作完成")

    def cancel(self):
        self.cancel_flag.value = 1
        messagebox.showinfo("取消", "操作已取消")
        self.reset_ui()

    def export_log(self):
        log_content = self.result_text.get('1.0', 'end')
        if not log_content.strip():
            messagebox.showinfo("提示", "没有日志内容可导出")
            return
        
        log_file = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if log_file:
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write(log_content)
            messagebox.showinfo("导出成功", f"日志已导出到 {log_file}")

    def update_checkboxes(self):
        # 确保在选择特定文件类型时取消"所有文件"单选按钮的选中状态
        if self.video_var.get() or self.image_var.get() or self.office_var.get():
            self.file_type_var.set(-1)

    def update_radiobutton(self):
        # 确保在选择"所有文件"时取消其他复选框的选中状态
        if self.file_type_var.get() == 0:
            self.video_var.set(False)
            self.image_var.set(False)
            self.office_var.set(False)
        # 重新启用复选框
        self.video_check.config(state="normal")
        self.image_check.config(state="normal")
        self.office_check.config(state="normal")

def process_file(args):
    file_path, current_folder = args
    file_hash = hash_file(file_path)
    if file_hash:
        return (file_path, file_hash, current_folder)
    return None

def hash_file(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
    except IOError:
        return None
    return hasher.hexdigest()

def merge_file_group(args):
    files, merged_dir = args
    main_file = files[0]
    base_name = os.path.basename(main_file)
    new_path = os.path.join(merged_dir, base_name)
    
    try:
        shutil.copy2(main_file, new_path)
        deleted_files = []
        for file in files[1:]:
            try:
                os.remove(file)
                deleted_files.append(file)
            except Exception as e:
                return (main_file, None, str(e))
        return (main_file, deleted_files, None)
    except Exception as e:
        return (main_file, None, str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = FileMerger(root)
    root.mainloop()

def hash_file(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            buf = f.read(65536)
            while len(buf) > 0:
                hasher.update(buf)
                buf = f.read(65536)
    except IOError:
        return None
    return hasher.hexdigest()

def merge_file_group(args):
    files, merged_dir = args
    main_file = files[0]
    base_name = os.path.basename(main_file)
    new_path = os.path.join(merged_dir, base_name)
    
    try:
        shutil.copy2(main_file, new_path)
        deleted_files = []
        for file in files[1:]:
            try:
                os.remove(file)
                deleted_files.append(file)
            except Exception as e:
                return (main_file, None, str(e))
        return (main_file, deleted_files, None)
    except Exception as e:
        return (main_file, None, str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = FileMerger(root)
    root.mainloop()