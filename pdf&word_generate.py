import pandas as pd
from docxtpl import DocxTemplate
from docx2pdf import convert
import xlwt
import math
import os

company_name="初檢_{}_{}年{}弱點掃描初檢_"
time=" "
c=" "

def check_dir(c):
    if not os.path.isdir(c):
        os.mkdir(c)
# read the data form excel
def excel_data_read(data_name):
    df = pd.read_excel(data_name)       #a = df.loc[:,["主機名稱"]].values
    try :
         data_len= df.index.stop
         data_array=df.values
    except :
         data_len=0
         data_array=0
    return data_len,data_array
def no_vulnerability(context,ip,dp):
    # enter data into the docx template
    doc = DocxTemplate("template_with_no_vulnerability.docx")
    doc.render(context)
    out_name = company_name + ip + ".docx"
    print("===============儲存資料",out_name,"=======")

    check_dir(dp)
    doc.save("{}/{}".format(dp,out_name))
    # generate pdf
    convert("{}/{}".format(dp,out_name))
def with_onevulnerability(context,ip,dp,detail_data):

    #page 2 to 3
    s_Level=nan_check(detail_data[0][2])
    s_Name=nan_check(detail_data[0][1])
    s_TCP =nan_check(detail_data[0][3])
    s_CVE=nan_check(detail_data[0][5])
    s_category=nan_check(detail_data[0][4])
    s_Overview=nan_check(detail_data[0][6])
    s_Explanation=nan_check(detail_data[0][7])  #說明
    s_Other=nan_check(detail_data[0][4])               #其他資訊
    s_attack=nan_check(detail_data[0][8])#有功攻擊程式
    s_EAR=nan_check(detail_data[0][9])  #攻擊難易度
    s_VD=nan_check(detail_data[0][11])#弱點公布
    s_VFD=nan_check(detail_data[0][12])#修補程式公布日期
    s_PD=nan_check(detail_data[0][13])   #Plugin公布日期
    s_PFD=nan_check(detail_data[0][14])   #Plugin修正日期
    s_Link=nan_check(detail_data[0][15])   #參考資訊
    s_AAA = nan_check(detail_data[0][16])  # 弱點修補建議
    s_PO = nan_check(detail_data[0][17])  # 弱點作證資料
    LT ={'number': "1",'level':s_Level,'name':s_Name,'tcp':s_TCP,'CVE':s_CVE,'category':s_category,'Overview':s_Overview,'Explanation':s_Explanation,'Other':s_Other,'attack':s_attack,'EAR':s_EAR,'VD':s_VD,'VFD':s_VFD,'PD':s_PD,'PFD':s_PFD,'Link':s_Link,'AAA':s_AAA,'PO':s_PO}

    context['list']=LT




    print("=================read the ip detail===========")

    # enter data into the docx template
    doc = DocxTemplate("template_with_one_vulnerability.docx")
    doc.render(context)
    #creat the docx and pdf with the effective name
    outputname="(Y)"+company_name+ip+".docx"
    print("===============儲存資料",outputname,"=======")
    check_dir(dp)
    doc.save("{}/{}".format(dp,outputname))
    convert("{}/{}".format(dp,outputname))
def with_twovulnerability(context,ip,dp,detail_data):

    t_list=[]
    for i  in range(2):
        s_Level=nan_check(detail_data[i][2])
        s_Name=nan_check(detail_data[i][1])
        s_TCP =nan_check(detail_data[i][3])
        s_CVE=nan_check(detail_data[i][5])
        s_category=nan_check(detail_data[i][4])
        s_Overview=nan_check(detail_data[i][6])
        s_Explanation=nan_check(detail_data[i][7])  #說明
        s_Other=nan_check(detail_data[i][4])               #其他資訊
        s_attack=nan_check(detail_data[i][8])#有功攻擊程式
        s_EAR=nan_check(detail_data[i][9])  #攻擊難易度
        s_VD=nan_check(detail_data[i][11])#弱點公布
        s_VFD=nan_check(detail_data[i][12])#修補程式公布日期
        s_PD=nan_check(detail_data[i][13] )  #Plugin公布日期
        s_PFD=nan_check(detail_data[i][14] )  #Plugin修正日期
        s_Link=nan_check(detail_data[i][15] )  #參考資訊
        s_AAA =nan_check(detail_data[i][16])   # 弱點修補建議
        s_PO =nan_check(detail_data[i][17])   # 弱點作證資料
        LT ={'number': i+1,'level':s_Level,'name':s_Name,'tcp':s_TCP,'CVE':s_CVE,'category':s_category,'Overview':s_Overview,'Explanation':s_Explanation,'Other':s_Other,'attack':s_attack,'EAR':s_EAR,'VD':s_VD,'VFD':s_VFD,'PD':s_PD,'PFD':s_PFD,'Link':s_Link,'AAA':s_AAA,'PO':s_PO}
        t_list.append(LT)
    

    context['list'] = t_list
    # t_list=[]
    # t_list.append(List)
    # context['list']=t_list

    print("=================read the ip detail===========")

    # enter data into the docx template
    doc = DocxTemplate("template_with_two_vulnerability.docx")
    doc.render(context)
    #creat the docx and pdf with the effective name
    outputname="(Y)"+company_name+ip+".docx"
    print("===============儲存資料",outputname,"=======")
    check_dir(dp)
    doc.save("{}/{}".format(dp,outputname))
    convert("{}/{}".format(dp,outputname))
def with_threevulnerability(context,ip,dp,detail_data,data_count):
	
    t_list=[]
    #page 2 to 3
    for i  in range(data_count):
        s_Level=nan_check(detail_data[i][2])
        s_Name=nan_check(detail_data[i][1])
        s_TCP =nan_check(detail_data[i][3])
        s_CVE=nan_check(detail_data[i][5])
        s_category=nan_check(detail_data[i][4])
        s_Overview=nan_check(detail_data[i][6])
        s_Explanation=nan_check(detail_data[i][7])  #說明
        s_Other=nan_check(detail_data[i][4])               #其他資訊
        s_attack=nan_check(detail_data[i][8])#有功攻擊程式
        s_EAR=nan_check(detail_data[i][9])  #攻擊難易度
        s_VD=nan_check(detail_data[i][11])#弱點公布
        s_VFD=nan_check(detail_data[i][12])#修補程式公布日期
        s_PD=nan_check(detail_data[i][13] )  #Plugin公布日期
        s_PFD=nan_check(detail_data[i][14] )  #Plugin修正日期
        s_Link=nan_check(detail_data[i][15] )  #參考資訊
        s_AAA =nan_check(detail_data[i][16])   # 弱點修補建議
        s_PO =nan_check(detail_data[i][17])   # 弱點作證資料
        LT ={'number': i+1,'level':s_Level,'name':s_Name,'tcp':s_TCP,'CVE':s_CVE,'category':s_category,'Overview':s_Overview,'Explanation':s_Explanation,'Other':s_Other,'attack':s_attack,'EAR':s_EAR,'VD':s_VD,'VFD':s_VFD,'PD':s_PD,'PFD':s_PFD,'Link':s_Link,'AAA':s_AAA,'PO':s_PO}
        t_list.append(LT)
	
    context['list'] = t_list
    print("=================read the ip detail===========")
    
    # enter data into the docx template
    
    doc = DocxTemplate("template_with_three_vulnerability.docx")
    doc.render(context)
    check_dir(dp)
    #creat the docx and pdf with the effective name
    if data_count == 3:
        outputname="(Y)"+company_name+ip+".docx"
        print("===============儲存資料",outputname,"=======")
        doc.save("{}/{}".format(dp,outputname))
        convert("{}/{}".format(dp,outputname))
    else:
        outputname="(XXXXXX)"+company_name+ip+".docx"
        print("===============儲存資料",outputname,"=======")
        doc.save("{}/{}".format(dp,outputname))
    
def nan_check(temp):
    
    if temp != temp:
        return " "
    else :
        #print (temp)
        return temp

def main():


    #initialization
    book = xlwt.Workbook(encoding='utf-8', style_compression=0)
    sheet = book.add_sheet('Vulnerability_status', cell_overwrite_ok=True)
    
    count=[0,0,0,0,0]
    sheet.write(0, 0, "無弱點")
    sheet.write(0, 2, "一個弱點")
    sheet.write(0, 4, "兩個弱點")
    sheet.write(0, 6, "三個弱點")
    sheet.write(0, 8, "需要調整")
    print("=====================reading excel===========================")
    (len, computer_list) = excel_data_read('各科組主機清單.xlsx')

    # processing data
    for i  in range(len):
        print("============================讀取資料如下所示=========================")
        print ("部門",computer_list[i][2],"主機名稱:",computer_list[i][3],"作業系統:",computer_list[i][4],"IP:",computer_list[i][5])

        # get some basic data , ip,os,use,dep..
        s_Ip=computer_list[i][5]
        s_Os=computer_list[i][4]
        s_Use=computer_list[i][3]
        s_Department=computer_list[i][2]
        context = { 'ip' : s_Ip ,'ip' : s_Ip,'os' : s_Os,'use' : s_Use, 'Department' : s_Department,'time':time,'c':c}


        temp="out/{}.xlsx".format(s_Ip)
        (len2,detail_list)=excel_data_read(temp)


        if len2 == 0 :
            print (s_Ip,"no vulnerability")
            no_vulnerability(context,s_Ip,s_Department)
            count[0] += 1
            sheet.write(count[0], 0, s_Ip)
            sheet.write(count[0], 1, s_Department)
        elif len2 ==1:
            print (s_Ip, "one vulnerability")
            with_onevulnerability(context,s_Ip,s_Department,detail_list)
            count[1] += 1
            sheet.write(count[1], 2, s_Ip)
            sheet.write(count[1], 3, s_Department)
            print (detail_list)
            with_onevulnerability(context, s_Ip, s_Department,detail_list)
        elif len2 ==2 :
            print (s_Ip, "two vulnerability")
            count[2]+=1
            sheet.write(count[2], 4, s_Ip)
            sheet.write(count[2], 5, s_Department)
            with_twovulnerability(context, s_Ip, s_Department,detail_list)
        elif len2 ==3 :
            print (s_Ip, "three vulnerability")
            count[3]+=1
            sheet.write(count[3], 6, s_Ip)
            sheet.write(count[3], 7, s_Department)
            with_threevulnerability(context, s_Ip, s_Department,detail_list,len2)
        else :
            count[4]+=1
            print (s_Ip, "more than three vulnerability")
            sheet.write(count[4], 8, s_Ip)
            sheet.write(count[4], 9, s_Department)
            with_threevulnerability(context, s_Ip, s_Department,detail_list,len2)

    book.save('Vulnerability_status.xls')
    print("=======================")
    print ("all done")
    print ("the count of no vulnerability  is {}".format(count[0]))
    print ("the count of one vulnerability  is {}".format(count[1]))
    print ("the count of two  vulnerability  is {}".format(count[2]))
    print ("the count of three  vulnerability  is {}".format(count[3]))
    if  count[4] != 0 :
        print  ("something  wrong ,there are  {} ip  have problen".format(count[4]))

if __name__=='__main__':
    flag = 0
    while(flag == 0):
        c = input("請輸入公司名稱(ex:第一金投信):")
        y = input("請輸入年度 (ex:109):")
        d = input("請輸入時間點_檔案命名用:(ex:上半年度)")
        company_name=company_name.format(c,y,d)
        print("檔案命名方式為:"+company_name)
        f = input("檔案名稱是否正確(Y/N)")
        if f == "Y":
            flag = 1
        else :
            print("請重新輸入")    

    time = input("請輸入掃描時間_格式 (ex:2020-04-24):")
    
    main()

# Data form  https://www.itread01.com/content/1547454061.html
