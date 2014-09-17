tar zxvf Electrum-LTC-1.9.8.5.tar.gz
cd Electrum-LTC-1.9.8.5

cp ~/.projects/electrum-tpc/electrum-tpc ~/.projects/electrum-tpc-winbuild/Electrum-LTC-1.9.8.5/

mv  ~/.projects/electrum-tpc-winbuild/Electrum-LTC-1.9.8.5/electrum-ltc ~/TRASH/

cp -r ~/.projects/electrum-tpc/gui ~/.projects/electrum-tpc-winbuild/Electrum-LTC-1.9.8.5/

cp -r ~/.projects/electrum-tpc/lib ~/.projects/electrum-tpc-winbuild/Electrum-LTC-1.9.8.5/

cp -r ~/.projects/electrum-tpc/plugins ~/.projects/electrum-tpc-winbuild/Electrum-LTC-1.9.8.5/

tar zcvf Electrum-TPC-1.9.8.5.tar.gz ./*
mv Electrum-TPC-1.9.8.5.tar.gz   ~/.projects/electrum-tpc-winbuild/source/
cd ..
./build-tpc 1.9.8.5
rm -rf Electrum-LTC-1.9.8.5


