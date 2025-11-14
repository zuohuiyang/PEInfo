#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE Analyzer GUI 界面测试脚本
模拟界面点击操作来测试功能
"""

import win32gui
import win32con
import win32api
import time
import os
import sys

def find_window_by_title(title):
    """通过标题查找窗口"""
    try:
        hwnd = win32gui.FindWindow(None, title)
        return hwnd
    except:
        return None

def click_button(hwnd, button_text):
    """点击指定文本的按钮"""
    try:
        # 查找按钮
        button_hwnd = win32gui.FindWindowEx(hwnd, 0, None, button_text)
        if button_hwnd:
            # 发送点击消息
            win32api.SendMessage(button_hwnd, win32con.BM_CLICK, 0, 0)
            return True
    except:
        pass
    return False

def set_edit_text(hwnd, edit_id, text):
    """设置编辑框文本"""
    try:
        edit_hwnd = win32gui.FindWindowEx(hwnd, 0, "Edit", None)
        if edit_hwnd:
            win32api.SendMessage(edit_hwnd, win32con.WM_SETTEXT, 0, text)
            return True
    except:
        pass
    return False

def simulate_gui_test():
    """模拟GUI界面测试"""
    print("🔍 正在查找 PE Analyzer 窗口...")
    
    # 查找主窗口
    hwnd = find_window_by_title("PE Analyzer & Hash Calculator")
    if not hwnd:
        print("❌ 未找到 PE Analyzer 窗口，请确保程序已运行")
        return False
    
    print("✅ 找到 PE Analyzer 窗口")
    
    # 获取窗口位置和大小
    rect = win32gui.GetWindowRect(hwnd)
    x, y, width, height = rect[0], rect[1], rect[2] - rect[0], rect[3] - rect[1]
    print(f"📐 窗口位置: ({x}, {y}), 大小: {width}x{height}")
    
    # 等待界面加载
    time.sleep(2)
    
    print("\n🧪 开始界面测试:")
    
    # 测试1: 点击"Browse..."按钮
    print("1️⃣ 测试文件浏览功能...")
    if click_button(hwnd, "Browse..."):
        print("   ✅ 点击了 Browse... 按钮")
        time.sleep(1)
    else:
        print("   ❌ 未找到 Browse... 按钮")
    
    # 测试2: 切换到哈希计算标签页
    print("2️⃣ 测试标签页切换...")
    # 查找标签控件并切换到第二个标签
    tab_hwnd = win32gui.FindWindowEx(hwnd, 0, "SysTabControl32", None)
    if tab_hwnd:
        # 发送消息切换到第二个标签 (索引1)
        win32api.SendMessage(tab_hwnd, win32con.TCM_SETCURSEL, 1, 0)
        print("   ✅ 切换到 Hash Calculator 标签页")
        time.sleep(1)
    else:
        print("   ❌ 未找到标签控件")
    
    # 测试3: 在哈希页面输入文本
    print("3️⃣ 测试哈希计算功能...")
    # 查找编辑框（可能有多个，这里简化处理）
    child_windows = []
    win32gui.EnumChildWindows(hwnd, lambda hwnd, param: param.append(hwnd), child_windows)
    
    edit_count = 0
    for child in child_windows:
        class_name = win32gui.GetClassName(child)
        if class_name == "Edit":
            edit_count += 1
            if edit_count == 2:  # 第二个编辑框通常是输入框
                win32api.SendMessage(child, win32con.WM_SETTEXT, 0, "Hello PE Analyzer!")
                print("   ✅ 在哈希输入框中输入了测试文本")
                break
    
    # 测试4: 点击哈希计算按钮
    if click_button(hwnd, "Calculate Hash"):
        print("   ✅ 点击了 Calculate Hash 按钮")
        time.sleep(1)
    else:
        print("   ❌ 未找到 Calculate Hash 按钮")
    
    # 测试5: 切换回PE分析标签页
    print("4️⃣ 测试拖拽功能准备...")
    if tab_hwnd:
        win32api.SendMessage(tab_hwnd, win32con.TCM_SETCURSEL, 0, 0)
        print("   ✅ 切换回 PE Analysis 标签页")
        time.sleep(1)
    
    print("\n🎉 GUI界面测试完成！")
    print("💡 您可以手动拖拽文件到程序窗口进行进一步测试")
    
    return True

def main():
    """主函数"""
    print("🚀 PE Analyzer GUI 界面测试工具")
    print("=" * 40)
    
    # 检查程序是否运行
    hwnd = find_window_by_title("PE Analyzer & Hash Calculator")
    if not hwnd:
        print("⚠️  PE Analyzer 程序未运行")
        print("🔄 正在启动程序...")
        
        # 启动程序
        exe_path = r"C:\project\petools\build\Release\PEAnalyzer.exe"
        if os.path.exists(exe_path):
            try:
                os.startfile(exe_path)
                print("⏳ 等待程序启动...")
                time.sleep(3)
            except Exception as e:
                print(f"❌ 启动程序失败: {e}")
                return
        else:
            print("❌ 未找到 PEAnalyzer.exe")
            return
    
    # 运行GUI测试
    simulate_gui_test()
    
    print("\n✨ 测试脚本执行完毕")
    print("🔧 您可以手动操作程序进行更多测试")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n🛑 测试被用户中断")
    except Exception as e:
        print(f"\n💥 测试过程中出现错误: {e}")