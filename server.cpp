/*
 * VPN Tunnel GUI Server - Modernized Edition
 * 
 * Dependencies (header-only libraries):
 * - cpp-httplib: https://github.com/yhirose/cpp-httplib
 * - nlohmann/json: https://github.com/nlohmann/json
 * 
 * Download these header files:
 * - httplib.h (place in project directory)
 * - nlohmann/json.hpp (create nlohmann/ folder and place json.hpp inside)
 * 
 * Build command:
 * g++ -std=c++17 -O2 -DWIN32_LEAN_AND_MEAN server.cpp -o server.exe -luser32 -lgdi32 -lcomctl32 -lws2_32 -static
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <thread>
#include <chrono>
#include <vector>
#include <map>
#include <mutex>
#include <sstream>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <commctrl.h>
#include <windowsx.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

// Window class names
#define WC_MAIN_WINDOW L"VPNTunnelServer"
#define WC_VIEWER_WINDOW L"VPNTunnelViewer"

// Control IDs
#define ID_CLIENT_LIST 1001
#define ID_REFRESH_BTN 1002
#define ID_MODE_TOGGLE 1003

// Custom messages
#define WM_UPDATE_CLIENT_LIST (WM_USER + 1)
#define WM_NEW_SCREEN_DATA (WM_USER + 2)

// Global variables
HINSTANCE g_hInstance = nullptr;
HWND g_hMainWnd = nullptr;
HWND g_hClientList = nullptr;
int g_serverPort = 443;
std::thread* g_serverThread = nullptr;
std::mutex g_clientsMutex;

// Client session data
struct ClientSession {
    std::string id;
    std::string client_ip;
    FILETIME last_seen;
    bool active;
    int width, height;
    std::vector<BYTE> screen_buffer;
    std::vector<std::string> pending_inputs;
    HWND viewer_window;
    bool is_connected;
};

std::map<std::string, ClientSession> g_clients;

// Remote desktop viewer window data
struct ViewerWindowData {
    std::string session_id;
    HBITMAP screen_bitmap;
    bool split_mode;
    int remote_width;
    int remote_height;
};

// Data decoder matching client implementation
class DataEncoder {
private:
    static const char chars[65];
    
public:
    static int decode(const char* input, int input_len, char* output, int max_output) {
        int T[256];
        for (int i = 0; i < 256; i++) T[i] = -1;
        for (int i = 0; i < 64; i++) T[(unsigned char)chars[i]] = i;
        
        int result_len = 0;
        int val = 0, valb = -8;
        
        for (int i = 0; i < input_len && result_len < max_output - 1; i++) {
            unsigned char c = input[i];
            if (T[c] == -1) break;
            val = (val << 6) + T[c];
            valb += 6;
            if (valb >= 0) {
                output[result_len++] = (char)((val >> valb) & 0xFF);
                valb -= 8;
            }
        }
        output[result_len] = '\0';
        return result_len;
    }
    
    static int encode(const char* input, int input_len, char* output, int max_output) {
        int result_len = 0;
        int val = 0, valb = -6;
        
        for (int i = 0; i < input_len && result_len < max_output - 4; i++) {
            val = (val << 8) + (unsigned char)input[i];
            valb += 8;
            while (valb >= 0 && result_len < max_output - 4) {
                output[result_len++] = chars[(val >> valb) & 0x3F];
                valb -= 6;
            }
        }
        if (valb > -6 && result_len < max_output - 4) {
            output[result_len++] = chars[((val << 8) >> (valb + 8)) & 0x3F];
        }
        while (result_len % 4 && result_len < max_output - 1) {
            output[result_len++] = '=';
        }
        output[result_len] = '\0';
        return result_len;
    }
};

const char DataEncoder::chars[65] = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm1234567890+/";

// RLE decompression
int decompressRLE(const char* compressed, int comp_len, char* output, int max_output) {
    int out_len = 0;
    
    for (int i = 0; i < comp_len && out_len < max_output; ) {
        if (i + 2 < comp_len && (unsigned char)compressed[i] == 0xFF) {
            unsigned char count = (unsigned char)compressed[i + 1];
            unsigned char value = (unsigned char)compressed[i + 2];
            for (int j = 0; j < count && out_len < max_output; j++) {
                output[out_len++] = value;
            }
            i += 3;
        } else {
            output[out_len++] = compressed[i];
            i++;
        }
    }
    return out_len;
}

// Extract data from VPN tunnel wrapper
int extractTunnelData(const char* wrapped, int wrapped_len, char* output, int max_output) {
    if (wrapped_len < 12) return 0;
    
    int start = 12;
    int end = wrapped_len;
    for (int i = start; i < wrapped_len - 1; i++) {
        if ((unsigned char)wrapped[i] == 0xFF && (unsigned char)wrapped[i+1] == 0xFF) {
            end = i;
            break;
        }
    }
    
    int copy_len = end - start;
    if (copy_len > max_output - 1) copy_len = max_output - 1;
    
    memcpy(output, wrapped + start, copy_len);
    output[copy_len] = '\0';
    return copy_len;
}

// Parse integer from JSON string
int parseInteger(const char* str, const char* key) {
    const char* pos = strstr(str, key);
    if (pos) {
        pos += strlen(key);
        return atoi(pos);
    }
    return 0;
}

// Extract JSON string value
int extractJsonString(const char* json, const char* key, char* output, int max_len) {
    char search_key[64];
    sprintf_s(search_key, sizeof(search_key), "\"%s\":\"", key);
    
    const char* start = strstr(json, search_key);
    if (start) {
        start += strlen(search_key);
        const char* end = strchr(start, '"');
        if (end) {
            int len = end - start;
            if (len < max_len) {
                memcpy(output, start, len);
                output[len] = '\0';
                return len;
            }
        }
    }
    return 0;
}

// Generate session key
void generateSessionKey(char* key, int max_len) {
    static DWORD seed = 0;
    if (seed == 0) seed = GetTickCount();
    
    const char hex[] = "0123456789abcdef";
    for (int i = 0; i < max_len - 1 && i < 32; i++) {
        seed = seed * 1103515245 + 12345;
        key[i] = hex[seed & 0xF];
    }
    key[max_len - 1] = '\0';
}

// Update client list in main window
void UpdateClientList() {
    if (!g_hClientList) return;
    
    std::lock_guard<std::mutex> lock(g_clientsMutex);
    
    // Clear existing items
    ListView_DeleteAllItems(g_hClientList);
    
    // Add clients
    int index = 0;
    for (auto& pair : g_clients) {
        ClientSession& client = pair.second;
        if (client.active) {
            LVITEMA item = {0};
            item.mask = LVIF_TEXT | LVIF_PARAM;
            item.iItem = index++;
            item.iSubItem = 0;
            item.pszText = const_cast<char*>(client.client_ip.c_str());
            item.lParam = (LPARAM)client.id.c_str();
            
            int itemIndex = ListView_InsertItem(g_hClientList, &item);
            
            // Add session ID
            ListView_SetItemText(g_hClientList, itemIndex, 1, const_cast<char*>(client.id.c_str()));
            
            // Add resolution
            char resolution[32];
            sprintf_s(resolution, sizeof(resolution), "%dx%d", client.width, client.height);
            ListView_SetItemText(g_hClientList, itemIndex, 2, resolution);
            
            // Add status
            ListView_SetItemText(g_hClientList, itemIndex, 3,
                                const_cast<char*>(client.is_connected ? "Connected" : "Idle"));
        }
    }
}

// Create screen bitmap from raw data
HBITMAP CreateScreenBitmap(const std::vector<BYTE>& screen_data, int width, int height) {
    if (screen_data.empty() || width == 0 || height == 0) return nullptr;
    
    HDC hdc = GetDC(nullptr);
    
    BITMAPINFO bmi = {0};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height; // Top-down
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 24;
    bmi.bmiHeader.biCompression = BI_RGB;
    
    void* pBits;
    HBITMAP hBitmap = CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &pBits, nullptr, 0);
    
    if (hBitmap && pBits) {
        int expected_size = width * height * 3;
        int copy_size = (screen_data.size() < expected_size) ? screen_data.size() : expected_size;
        memcpy(pBits, screen_data.data(), copy_size);
    }
    
    ReleaseDC(nullptr, hdc);
    return hBitmap;
}

// Queue input command for transmission
void QueueInputCommand(const std::string& session_id, const std::string& command) {
    std::lock_guard<std::mutex> lock(g_clientsMutex);
    auto it = g_clients.find(session_id);
    if (it != g_clients.end()) {
        it->second.pending_inputs.push_back(command);
    }
}

// Remote desktop viewer window procedure
LRESULT CALLBACK ViewerWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    ViewerWindowData* data = (ViewerWindowData*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
    
    switch (uMsg) {
    case WM_CREATE: {
        CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
        data = (ViewerWindowData*)cs->lpCreateParams;
        SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)data);
        
        // Create mode toggle button
        CreateWindowW(L"BUTTON", L"⚏", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     0, 0, 30, 25, hwnd, (HMENU)ID_MODE_TOGGLE, g_hInstance, nullptr);
        
        return 0;
    }
    
    case WM_SIZE: {
        // Reposition mode toggle button
        HWND hToggle = GetDlgItem(hwnd, ID_MODE_TOGGLE);
        if (hToggle) {
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            SetWindowPos(hToggle, HWND_TOP, clientRect.right - 35, 5, 30, 25, SWP_NOZORDER);
        }
        
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;
    }
    
    case WM_COMMAND: {
        if (LOWORD(wParam) == ID_MODE_TOGGLE) {
            if (data) {
                data->split_mode = !data->split_mode;
                InvalidateRect(hwnd, nullptr, TRUE);
            }
        }
        return 0;
    }
    
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        
        RECT clientRect;
        GetClientRect(hwnd, &clientRect);
        
        if (data && data->screen_bitmap) {
            HDC hdcMem = CreateCompatibleDC(hdc);
            HBITMAP hOldBitmap = (HBITMAP)SelectObject(hdcMem, data->screen_bitmap);
            
            BITMAP bm;
            GetObject(data->screen_bitmap, sizeof(bm), &bm);
            
            if (data->split_mode) {
                // Split mode: left half blank, right half remote screen
                int halfWidth = clientRect.right / 2;
                
                // Fill left half with gray
                RECT leftRect = {0, 0, halfWidth, clientRect.bottom};
                FillRect(hdc, &leftRect, (HBRUSH)(COLOR_BTNFACE + 1));
                
                // Draw text in left panel
                DrawTextA(hdc, "Tool Panel\n(Coming Soon)", -1, &leftRect, 
                         DT_CENTER | DT_VCENTER | DT_WORDBREAK);
                
                // Scale remote screen to right half
                StretchBlt(hdc, halfWidth, 0, halfWidth, clientRect.bottom,
                          hdcMem, 0, 0, bm.bmWidth, bm.bmHeight, SRCCOPY);
            } else {
                // Full mode: entire window shows remote screen
                StretchBlt(hdc, 0, 0, clientRect.right, clientRect.bottom,
                          hdcMem, 0, 0, bm.bmWidth, bm.bmHeight, SRCCOPY);
            }
            
            SelectObject(hdcMem, hOldBitmap);
            DeleteDC(hdcMem);
        } else {
            // No screen data - show waiting message
            FillRect(hdc, &clientRect, (HBRUSH)(COLOR_WINDOW + 1));
            
            char status[256];
            if (data) {
                sprintf_s(status, sizeof(status), "Connecting to %s...", data->session_id.c_str());
            } else {
                strcpy_s(status, sizeof(status), "No connection");
            }
            
            DrawTextA(hdc, status, -1, &clientRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        }
        
        EndPaint(hwnd, &ps);
        return 0;
    }
    
    case WM_LBUTTONDOWN: {
        if (data && data->screen_bitmap) {
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);
            
            if (data->split_mode) {
                // Adjust coordinates for split mode (only right half is active)
                int halfWidth = clientRect.right / 2;
                if (x >= halfWidth) {
                    x = ((x - halfWidth) * data->remote_width) / halfWidth;
                    y = (y * data->remote_height) / clientRect.bottom;
                } else {
                    return 0; // Click in left panel, ignore
                }
            } else {
                // Full mode coordinates
                x = (x * data->remote_width) / clientRect.right;
                y = (y * data->remote_height) / clientRect.bottom;
            }
            
            char command[128];
            sprintf_s(command, sizeof(command), "click:%d:%d", x, y);
            QueueInputCommand(data->session_id, command);
        }
        return 0;
    }
    
    case WM_RBUTTONDOWN: {
        if (data && data->screen_bitmap) {
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            
            int x = LOWORD(lParam);
            int y = HIWORD(lParam);
            
            if (data->split_mode) {
                int halfWidth = clientRect.right / 2;
                if (x >= halfWidth) {
                    x = ((x - halfWidth) * data->remote_width) / halfWidth;
                    y = (y * data->remote_height) / clientRect.bottom;
                } else {
                    return 0;
                }
            } else {
                x = (x * data->remote_width) / clientRect.right;
                y = (y * data->remote_height) / clientRect.bottom;
            }
            
            char command[128];
            sprintf_s(command, sizeof(command), "rightclick:%d:%d", x, y);
            QueueInputCommand(data->session_id, command);
        }
        return 0;
    }
    
    case WM_CHAR: {
        if (data) {
            char command[32];
            if (wParam == VK_RETURN) {
                strcpy_s(command, sizeof(command), "key:ENTER");
            } else if (wParam == VK_ESCAPE) {
                strcpy_s(command, sizeof(command), "key:ESCAPE");
            } else if (wParam >= 32 && wParam < 127) {
                sprintf_s(command, sizeof(command), "key:%c", (char)wParam);
            } else {
                return 0;
            }
            QueueInputCommand(data->session_id, command);
        }
        return 0;
    }
    
    case WM_CLOSE: {
        if (data) {
            // Mark client as disconnected
            std::lock_guard<std::mutex> lock(g_clientsMutex);
            auto it = g_clients.find(data->session_id);
            if (it != g_clients.end()) {
                it->second.viewer_window = nullptr;
                it->second.is_connected = false;
            }
            
            if (data->screen_bitmap) {
                DeleteObject(data->screen_bitmap);
            }
            delete data;
        }
        DestroyWindow(hwnd);
        return 0;
    }
    
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// Open remote desktop viewer window
void OpenViewerWindow(const std::string& session_id) {
    std::lock_guard<std::mutex> lock(g_clientsMutex);
    auto it = g_clients.find(session_id);
    if (it != g_clients.end()) {
        ClientSession& client = it->second;
        
        // Check if window already exists
        if (client.viewer_window && IsWindow(client.viewer_window)) {
            SetForegroundWindow(client.viewer_window);
            return;
        }
        
        // Create new viewer window data
        ViewerWindowData* data = new ViewerWindowData();
        data->session_id = session_id;
        data->screen_bitmap = nullptr;
        data->split_mode = false;
        data->remote_width = client.width;
        data->remote_height = client.height;
        
        // Create the viewer window
        char title[256];
        sprintf_s(title, sizeof(title), "Remote Desktop - %s (%s)", 
                 client.client_ip.c_str(), session_id.c_str());
        
        HWND hViewer = CreateWindowExA(
            0,
            "VPNTunnelViewer",
            title,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT, CW_USEDEFAULT, 1024, 768,
            nullptr, nullptr, g_hInstance, data
        );
        
        if (hViewer) {
            client.viewer_window = hViewer;
            client.is_connected = true;
            ShowWindow(hViewer, SW_SHOW);
            UpdateWindow(hViewer);
            
            // Update screen if we already have data
            if (!client.screen_buffer.empty()) {
                data->screen_bitmap = CreateScreenBitmap(client.screen_buffer, client.width, client.height);
                InvalidateRect(hViewer, nullptr, TRUE);
            }
        } else {
            delete data;
        }
    }
}

// Main window procedure
LRESULT CALLBACK MainWindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        // Initialize common controls
        InitCommonControls();
        
        // Create refresh button
        CreateWindowA("BUTTON", "Refresh", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
                     10, 10, 80, 30, hwnd, (HMENU)ID_REFRESH_BTN, g_hInstance, nullptr);
        
        // Create client list view
        g_hClientList = CreateWindowA(WC_LISTVIEW, "",
                                     WS_VISIBLE | WS_CHILD | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
                                     10, 50, 600, 300, hwnd, (HMENU)ID_CLIENT_LIST, g_hInstance, nullptr);
        
        // Set up list view columns
        LVCOLUMNA col = {0};
        col.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
        
        col.pszText = const_cast<char*>("Client IP");
        col.cx = 120;
        col.iSubItem = 0;
        ListView_InsertColumn(g_hClientList, 0, &col);
        
        col.pszText = const_cast<char*>("Session ID");
        col.cx = 140;
        col.iSubItem = 1;
        ListView_InsertColumn(g_hClientList, 1, &col);
        
        col.pszText = const_cast<char*>("Resolution");
        col.cx = 100;
        col.iSubItem = 2;
        ListView_InsertColumn(g_hClientList, 2, &col);
        
        col.pszText = const_cast<char*>("Status");
        col.cx = 80;
        col.iSubItem = 3;
        ListView_InsertColumn(g_hClientList, 3, &col);
        
        // Enable full row select
        ListView_SetExtendedListViewStyle(g_hClientList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        
        // Set window title
        SetWindowTextA(hwnd, "VPN Tunnel Server - Client Manager");
        
        return 0;
    }
    
    case WM_SIZE: {
        RECT clientRect;
        GetClientRect(hwnd, &clientRect);
        
        // Resize list view
        if (g_hClientList) {
            SetWindowPos(g_hClientList, nullptr, 10, 50, 
                        clientRect.right - 20, clientRect.bottom - 60, SWP_NOZORDER);
        }
        return 0;
    }
    
    case WM_COMMAND: {
        if (LOWORD(wParam) == ID_REFRESH_BTN) {
            UpdateClientList();
        }
        return 0;
    }
    
    case WM_NOTIFY: {
        LPNMHDR pnmh = (LPNMHDR)lParam;
        if (pnmh->idFrom == ID_CLIENT_LIST && pnmh->code == NM_DBLCLK) {
            int selected = ListView_GetNextItem(g_hClientList, -1, LVNI_SELECTED);
            if (selected != -1) {
                char session_id[64];
                ListView_GetItemText(g_hClientList, selected, 1, session_id, sizeof(session_id));
                OpenViewerWindow(std::string(session_id));
            }
        }
        return 0;
    }
    
    case WM_UPDATE_CLIENT_LIST: {
        UpdateClientList();
        return 0;
    }
    
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
        
    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// HTTP response sender
void sendHttpResponse(SOCKET client_socket, int status_code, const char* content_type, const char* body) {
    char response[8192];
    const char* status_text = (status_code == 200) ? "OK" : "Not Found";
    
    int body_len = body ? strlen(body) : 0;
    
    int header_len = sprintf_s(response, sizeof(response),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n",
        status_code, status_text, content_type, body_len);
    
    send(client_socket, response, header_len, 0);
    if (body && body_len > 0) {
        send(client_socket, body, body_len, 0);
    }
}

// Server worker thread
void ServerWorkerThread() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }
    
    SOCKET server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        WSACleanup();
        return;
    }
    
    sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons((u_short)g_serverPort);
    
    if (bind(server_socket, (sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(server_socket);
        WSACleanup();
        return;
    }
    
    if (listen(server_socket, 5) == SOCKET_ERROR) {
        closesocket(server_socket);
        WSACleanup();
        return;
    }
    
    char status[256];
    sprintf_s(status, sizeof(status), "VPN Tunnel Server - Listening on port %d", g_serverPort);
    SetWindowTextA(g_hMainWnd, status);
    
    while (true) {
        sockaddr_in client_addr;
        int client_addr_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(server_socket, (sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) break;
        
        // Handle request in separate thread
        std::thread([client_socket, client_addr]() {
            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            
            char buffer[8192];
            int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
            
            if (bytes_received > 0) {
                buffer[bytes_received] = '\0';
                
                char method[16], path[256], version[16];
                if (sscanf_s(buffer, "%15s %255s %15s", method, sizeof(method), 
                           path, sizeof(path), version, sizeof(version)) == 3) {
                    
                    if (strcmp(method, "GET") == 0 && strcmp(path, "/vpn/auth") == 0) {
                        // Generate session for new tunnel
                        char session_id[33];
                        generateSessionKey(session_id, sizeof(session_id));
                        session_id[16] = '\0';
                        
                        std::lock_guard<std::mutex> lock(g_clientsMutex);
                        ClientSession& client = g_clients[session_id];
                        client.id = session_id;
                        client.client_ip = client_ip;
                        GetSystemTimeAsFileTime(&client.last_seen);
                        client.active = true;
                        client.width = 0;
                        client.height = 0;
                        client.viewer_window = nullptr;
                        client.is_connected = false;
                        
                        char response_body[256];
                        sprintf_s(response_body, sizeof(response_body), 
                                 "{\"session\":\"%s\",\"status\":\"authenticated\"}", session_id);
                        sendHttpResponse(client_socket, 200, "application/json", response_body);
                        
                        // Update client list in UI
                        PostMessage(g_hMainWnd, WM_UPDATE_CLIENT_LIST, 0, 0);
                        
                    } else if (strcmp(method, "POST") == 0 && strncmp(path, "/vpn/tunnel/", 12) == 0) {
                        // Handle screen data transmission
                        char session_id[64];
                        strcpy_s(session_id, sizeof(session_id), path + 12);
                        
                        const char* body_start = strstr(buffer, "\r\n\r\n");
                        if (body_start) {
                            body_start += 4;
                            int body_len = bytes_received - (body_start - buffer);
                            
                            char tunnel_data[4096];
                            int tunnel_len = extractTunnelData(body_start, body_len, tunnel_data, sizeof(tunnel_data));
                            
                            if (tunnel_len > 0) {
                                int width = parseInteger(tunnel_data, "\"width\":");
                                int height = parseInteger(tunnel_data, "\"height\":");
                                
                                char encoded_data[2048];
                                if (extractJsonString(tunnel_data, "data", encoded_data, sizeof(encoded_data)) > 0) {
                                    char decoded[4096];
                                    int decoded_len = DataEncoder::decode(encoded_data, strlen(encoded_data), 
                                                                        decoded, sizeof(decoded));
                                    
                                    if (decoded_len > 0) {
                                        std::vector<BYTE> screen_data(width * height * 3);
                                        int screen_len = decompressRLE(decoded, decoded_len, 
                                                                     (char*)screen_data.data(), screen_data.size());
                                        
                                        std::lock_guard<std::mutex> lock(g_clientsMutex);
                                        auto it = g_clients.find(session_id);
                                        if (it != g_clients.end()) {
                                            ClientSession& client = it->second;
                                            client.width = width;
                                            client.height = height;
                                            client.screen_buffer = screen_data;
                                            GetSystemTimeAsFileTime(&client.last_seen);
                                            
                                            // Update viewer window if open
                                            if (client.viewer_window && IsWindow(client.viewer_window)) {
                                                ViewerWindowData* data = (ViewerWindowData*)GetWindowLongPtr(
                                                    client.viewer_window, GWLP_USERDATA);
                                                if (data) {
                                                    if (data->screen_bitmap) {
                                                        DeleteObject(data->screen_bitmap);
                                                    }
                                                    data->screen_bitmap = CreateScreenBitmap(screen_data, width, height);
                                                    data->remote_width = width;
                                                    data->remote_height = height;
                                                    InvalidateRect(client.viewer_window, nullptr, FALSE);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        
                        sendHttpResponse(client_socket, 200, "text/plain", "OK");
                        
                    } else if (strcmp(method, "GET") == 0 && strncmp(path, "/vpn/control/", 13) == 0) {
                        // Handle input command requests
                        char session_id[64];
                        strcpy_s(session_id, sizeof(session_id), path + 13);
                        
                        std::lock_guard<std::mutex> lock(g_clientsMutex);
                        auto it = g_clients.find(session_id);
                        if (it != g_clients.end() && !it->second.pending_inputs.empty()) {
                            std::string input_cmd = it->second.pending_inputs.front();
                            it->second.pending_inputs.erase(it->second.pending_inputs.begin());
                            
                            char encoded_cmd[256];
                            DataEncoder::encode(input_cmd.c_str(), input_cmd.length(), 
                                              encoded_cmd, sizeof(encoded_cmd));
                            
                            char response_body[512];
                            sprintf_s(response_body, sizeof(response_body), "{\"input\":\"%s\"}", encoded_cmd);
                            sendHttpResponse(client_socket, 200, "application/json", response_body);
                        } else {
                            sendHttpResponse(client_socket, 200, "application/json", "{}");
                        }
                        
                    } else {
                        sendHttpResponse(client_socket, 404, "text/plain", "Not Found");
                    }
                }
            }
            
            closesocket(client_socket);
        }).detach();
    }
    
    closesocket(server_socket);
    WSACleanup();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInstance = hInstance;
    
    // Parse command line for port
    if (strlen(lpCmdLine) > 0) {
        g_serverPort = atoi(lpCmdLine);
    }
    
    // Register main window class
    WNDCLASSW wc = {0};
    wc.lpfnWndProc = MainWindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = WC_MAIN_WINDOW;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    
    if (!RegisterClassW(&wc)) {
        return 1;
    }
    
    // Register viewer window class
    WNDCLASSW vc = {0};
    vc.lpfnWndProc = ViewerWindowProc;
    vc.hInstance = hInstance;
    vc.lpszClassName = WC_VIEWER_WINDOW;
    vc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    vc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    vc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    
    if (!RegisterClassW(&vc)) {
        return 1;
    }
    
    // Create main window
    g_hMainWnd = CreateWindowW(
        WC_MAIN_WINDOW,
        L"VPN Tunnel Server",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 640, 400,
        nullptr, nullptr, hInstance, nullptr
    );
    
    if (!g_hMainWnd) {
        return 1;
    }
    
    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);
    
    // Start server thread
    g_serverThread = new std::thread(ServerWorkerThread);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}