#Build di n3iwf
#sudo docker build -t n3iwf_local -f ./n3iwfCustom/Dockerfile ./n3iwfCustom/;
sudo docker build -t n3iwf_local2 -f ./nf_n3iwf/Dockerfile ./nf_n3iwf/;

#Build di AMF
#sudo docker build -t amf_local -f ./amfCustom/Dockerfile ./amfCustom/;
sudo docker build -t amf_local2 -f ./nf_amf/Dockerfile ./nf_amf/;

#Build di SMF
#sudo docker build -t smf_local -f ./smfCustom/Dockerfile ./smfCustom/;
sudo docker build -t smf_local2 -f ./nf_smf/Dockerfile ./nf_smf/;
sudo docker compose -f dcb.yaml build;

#Build di E2 Node Simulator
sudo chmod +x ./e2sim/build_e2sim;

#Build di E2 Node --Non necessario visto che builda all'interno del container
#cd ./e2sim
#./build_e2sim --clean;
#./build_e2sim;
