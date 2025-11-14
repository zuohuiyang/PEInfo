#pragma once

#include "stdafx.h"
#include "PEParser.h"
#include "HashCalculator.h"

class CPEAnalyzerApp {
public:
    CPEAnalyzerApp();
    ~CPEAnalyzerApp();

    BOOL InitInstance(HINSTANCE hInstance);
    int Run();
    void Exit();

private:
    static LRESULT CALLBACK WindowProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);

    BOOL CreateMainWindow();
    BOOL CreateControls();
    void InitializeTabs();
    void ShowTab(int tabIndex);
    
    // PE分析功能
    void OnPEBrowse();
    void OnPEAnalyze();
    void UpdatePETreeView();
    
    // 哈希计算功能
    void OnHashBrowse();
    void OnHashCalculate();
    void OnHashClear();
    void UpdateHashDataType();
    void UpdateHMACControls();

    // 工具函数
    std::wstring BrowseForFile(const std::wstring& title, const std::wstring& filter);
    void ShowError(const std::wstring& message);
    void ShowInfo(const std::wstring& message);

private:
    HINSTANCE m_hInstance;
    HWND m_hWnd;
    HWND m_hTabControl;
    HWND m_hPEGroupBox;
    HWND m_hHashGroupBox;
    
    // PE分析控件
    HWND m_hPEFilePath;
    HWND m_hPEBrowseButton;
    HWND m_hPEAnalyzeButton;
    HWND m_hPETreeView;
    HWND m_hPEStatus;
    
    // 哈希计算控件
    HWND m_hHashDataType;
    HWND m_hHashFilePath;
    HWND m_hHashBrowseButton;
    HWND m_hHashHMACCheck;
    HWND m_hHashKeyType;
    HWND m_hHashKeyValue;
    HWND m_hHashTimeLabel;
    HWND m_hHashCalculateButton;
    HWND m_hHashClearButton;
    
    // 哈希算法复选框和结果框
    std::map<HashAlgorithm, HWND> m_hashCheckBoxes;
    std::map<HashAlgorithm, HWND> m_hashResultBoxes;

    PEParser m_peParser;
    HashCalculator m_hashCalculator;
    
    int m_currentTab;
    std::wstring m_lastPEFile;
    std::wstring m_lastHashFile;
};