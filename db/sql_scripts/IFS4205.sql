-- we don't know how to generate schema ifs4205 (class Schema) :(
create table if not exists auth_group
(
	id int auto_increment
		primary key,
	name varchar(80) not null,
	constraint name
		unique (name)
)
;

create table if not exists auth_user
(
	id int auto_increment
		primary key,
	password varchar(128) not null,
	last_login datetime(6) null,
	is_superuser tinyint(1) not null,
	username varchar(150) not null,
	first_name varchar(30) not null,
	last_name varchar(150) not null,
	email varchar(254) not null,
	is_staff tinyint(1) not null,
	is_active tinyint(1) not null,
	date_joined datetime(6) not null,
	constraint username
		unique (username)
)
;

create table if not exists auth_user_groups
(
	id int auto_increment
		primary key,
	user_id int not null,
	group_id int not null,
	constraint auth_user_groups_user_id_group_id_94350c0c_uniq
		unique (user_id, group_id),
	constraint auth_user_groups_group_id_97559544_fk_auth_group_id
		foreign key (group_id) references auth_group (id),
	constraint auth_user_groups_user_id_6a12ed8b_fk_auth_user_id
		foreign key (user_id) references auth_user (id)
)
;

create table if not exists django_content_type
(
	id int auto_increment
		primary key,
	app_label varchar(100) not null,
	model varchar(100) not null,
	constraint django_content_type_app_label_model_76bd3d3b_uniq
		unique (app_label, model)
)
;

create table if not exists auth_permission
(
	id int auto_increment
		primary key,
	name varchar(255) not null,
	content_type_id int not null,
	codename varchar(100) not null,
	constraint auth_permission_content_type_id_codename_01ab375a_uniq
		unique (content_type_id, codename),
	constraint auth_permission_content_type_id_2f476e4b_fk_django_co
		foreign key (content_type_id) references django_content_type (id)
)
;

create table if not exists auth_group_permissions
(
	id int auto_increment
		primary key,
	group_id int not null,
	permission_id int not null,
	constraint auth_group_permissions_group_id_permission_id_0cd325b0_uniq
		unique (group_id, permission_id),
	constraint auth_group_permissio_permission_id_84c5c92e_fk_auth_perm
		foreign key (permission_id) references auth_permission (id),
	constraint auth_group_permissions_group_id_b120cbf9_fk_auth_group_id
		foreign key (group_id) references auth_group (id)
)
;

create table if not exists auth_user_user_permissions
(
	id int auto_increment
		primary key,
	user_id int not null,
	permission_id int not null,
	constraint auth_user_user_permissions_user_id_permission_id_14a6b632_uniq
		unique (user_id, permission_id),
	constraint auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm
		foreign key (permission_id) references auth_permission (id),
	constraint auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id
		foreign key (user_id) references auth_user (id)
)
;

create table if not exists django_admin_log
(
	id int auto_increment
		primary key,
	action_time datetime(6) not null,
	object_id longtext null,
	object_repr varchar(200) not null,
	action_flag smallint(5) unsigned not null,
	change_message longtext not null,
	content_type_id int null,
	user_id int not null,
	constraint django_admin_log_content_type_id_c4bce8eb_fk_django_co
		foreign key (content_type_id) references django_content_type (id),
	constraint django_admin_log_user_id_c564eba6_fk_auth_user_id
		foreign key (user_id) references auth_user (id)
)
;

create table if not exists django_migrations
(
	id int auto_increment
		primary key,
	app varchar(255) not null,
	name varchar(255) not null,
	applied datetime(6) not null
)
;

create table if not exists django_session
(
	session_key varchar(40) not null
		primary key,
	session_data longtext not null,
	expire_date datetime(6) not null
)
;

create index django_session_expire_date_a5c62663
	on django_session (expire_date)
;

create table if not exists webapp_patient
(
	id int auto_increment
		primary key,
	name varchar(100) not null,
	nric varchar(9) not null,
	gender varchar(6) not null,
	address varchar(100) not null,
	contact_number varchar(12) not null,
	date_of_birth datetime(6) not null
)
;

create table if not exists webapp_healthdata
(
	id int auto_increment
		primary key,
	type int not null,
	title varchar(100) not null,
	description varchar(1000) not null,
	date datetime(6) not null,
	patient_id int not null,
	constraint webapp_healthdata_patient_id_a5dc55b7_fk_webapp_patient_id
		foreign key (patient_id) references webapp_patient (id)
)
;

create table if not exists webapp_healthdatapermission
(
	id int auto_increment
		primary key,
	has_access tinyint(1) not null,
	date datetime(6) not null,
	health_data_id int not null,
	constraint webapp_healthdataper_health_data_id_fbc18989_fk_webapp_he
		foreign key (health_data_id) references webapp_healthdata (id)
)
;

create table if not exists webapp_healthdatapermission_patients
(
	id int auto_increment
		primary key,
	healthdatapermission_id int not null,
	patient_id int not null,
	constraint webapp_healthdatapermiss_healthdatapermission_id__43364bb8_uniq
		unique (healthdatapermission_id, patient_id),
	constraint webapp_healthdataper_healthdatapermission_d195a448_fk_webapp_he
		foreign key (healthdatapermission_id) references webapp_healthdatapermission (id),
	constraint webapp_healthdataper_patient_id_b8920c57_fk_webapp_pa
		foreign key (patient_id) references webapp_patient (id)
)
;

create table if not exists webapp_researcher
(
	id int auto_increment
		primary key,
	name varchar(100) not null,
	institution varchar(100) not null
)
;

create table if not exists webapp_therapist
(
	id int auto_increment
		primary key,
	name varchar(100) not null,
	designation varchar(45) not null,
	department varchar(45) not null,
	contact_number varchar(12) not null
)
;

create table if not exists webapp_isapatientof
(
	id int auto_increment
		primary key,
	has_read_access tinyint(1) not null,
	has_write_access tinyint(1) not null,
	patient_id int not null,
	therapist_id int not null,
	constraint webapp_isapatientof_patient_id_a48dd55a_fk_webapp_patient_id
		foreign key (patient_id) references webapp_patient (id),
	constraint webapp_isapatientof_therapist_id_1bf698e0_fk_webapp_therapist_id
		foreign key (therapist_id) references webapp_therapist (id)
)
;

create table if not exists webapp_userprofile
(
	id int auto_increment
		primary key,
	role int not null,
	patient_id int not null,
	therapist_id int not null,
	user_id int not null,
	constraint user_id
		unique (user_id),
	constraint webapp_userprofile_patient_id_c6802313_fk_webapp_patient_id
		foreign key (patient_id) references webapp_patient (id),
	constraint webapp_userprofile_therapist_id_610fc54d_fk_webapp_therapist_id
		foreign key (therapist_id) references webapp_therapist (id),
	constraint webapp_userprofile_user_id_052c96be_fk_auth_user_id
		foreign key (user_id) references auth_user (id)
)
;

create table if not exists webapp_visitrecord
(
	id int auto_increment
		primary key,
	date datetime(6) not null,
	patient_id int not null,
	therapist_id int not null,
	constraint webapp_visit_record_patient_id_f979f7cd_fk_webapp_patient_id
		foreign key (patient_id) references webapp_patient (id),
	constraint webapp_visit_record_therapist_id_99da10a4_fk_webapp_therapist_id
		foreign key (therapist_id) references webapp_therapist (id)
)
;

create table if not exists webapp_ward
(
	id int auto_increment
		primary key,
	name varchar(100) not null,
	policy int not null
)
;

create table if not exists webapp_ward_patients
(
	id int auto_increment
		primary key,
	ward_id int not null,
	patient_id int not null,
	constraint webapp_ward_patients_ward_id_patient_id_eb627ee6_uniq
		unique (ward_id, patient_id),
	constraint webapp_ward_patients_patient_id_f2b8ed4b_fk_webapp_patient_id
		foreign key (patient_id) references webapp_patient (id),
	constraint webapp_ward_patients_ward_id_ae1a0ad1_fk_webapp_ward_id
		foreign key (ward_id) references webapp_ward (id)
)
;

create table if not exists webapp_ward_therapists
(
	id int auto_increment
		primary key,
	ward_id int not null,
	therapist_id int not null,
	constraint webapp_ward_therapists_ward_id_therapist_id_d58b8eba_uniq
		unique (ward_id, therapist_id),
	constraint webapp_ward_therapis_therapist_id_095bd72f_fk_webapp_th
		foreign key (therapist_id) references webapp_therapist (id),
	constraint webapp_ward_therapists_ward_id_cfb7cb39_fk_webapp_ward_id
		foreign key (ward_id) references webapp_ward (id)
)
;

