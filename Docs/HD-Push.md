\*\*Thứ tự push code

# I.\*\**khi lỡ code mà chưa pull code mới nhất*



git stash -u #Lưu toàn bộ thay đổi hiện tại(code và các yều cầu mới làm) vào bộ nhớ tạm

git checkout main #về nhánh main pull tránh conflic code

git pull origin main #pull

git checkout -b feature/mssv-mudule-<Số mudule đang làm>

git merge main #Đồng bộ code mới nhất của main
git stash pop #Lấy lại các file
git add .

git commit -m "feat: <mục tiêu công việc ngắn gọn>"

git push -u origin feature/mssv-mudule-<số module hiện tại cần push>



# *II.push code khi đã pull*

git checkout main #về nhánh main pull tránh conflic code

git pull origin main #pull
-----xử lý code mới------
git checkout feature/mssv-mudule-<Số mudule đang làm>



git add .
git commit -m "feat: <mục tiêu công việc ngắn gọn>"

git push -u origin feature/mssv-mudule-<số module hiện tại cần push>

