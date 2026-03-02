#  Projet IoT Sécurisé – Authentification Forte avec Secure Element Virtuel

##  Description

Ce projet implémente une architecture IoT sécurisée basée sur :

- Authentification forte des objets
- Secure Element virtuel (SoftHSM2)
- PKCS#11 pour l'accès sécurisé aux clés
- Vérification côté serveur
- Base pour mTLS + MQTT
- Détection d’anomalies (IA – optionnel)

L’objectif est de garantir :
- La clé privée ne quitte jamais le Secure Element  
- Protection contre le clonage  
- Vérification cryptographique côté serveur  
- Architecture extensible vers mTLS et MQTT

 ##  Architecture du Projet
projet-iot-securise/
│
├── devices/
│ ├── secure_element/
│ └── agent/
│
├── pki/
│
├── platform/
│ ├── mqtt/
│ ├── backend/
│ ├── ai_engine/
│ └── monitoring/
│
├── tests/
└── docker/

##  Environnement d’installation

### Outils utilisés

- VirtualBox
- Ubuntu 22.04
- Python 3
- SoftHSM2 (Secure Element virtuel)
- OpenSSL
- PKCS#11 (API cryptographique)
- Docker

---

#  Partie 1 : Secure Element (SoftHSM)

##  Initialisation du Token

Un token SoftHSM représente un Secure Element virtuel.

softhsm2-util --init-token --slot 0 \
--label "iot_secure_element" \
--so-pin 1234 \
--pin 0000 


 1. Devices (Côté Objet IoT)

Contient tout ce qui représente le logiciel embarqué de l’objet ou sa simulation.

## secure_element/

Simule un composant matériel sécurisé (Secure Element).

- se_module.py : Interface avec le Secure Element via PKCS#11 pour les opérations cryptographiques.

- init_token.sh : Script d’initialisation du token (création du Secure Element virtuel, PIN, clés).

## agent/

Représente l’objet IoT communicant avec la plateforme.

- agent.py : Client MQTT utilisant un certificat client pour l’authentification.

- requirements.txt : Dépendances Python nécessaires à l’exécution de l’agent.

2. PKI (Infrastructure à Clé Publique)

Gère l’identité cryptographique des composants.

ca.crt : Certificat public de l’Autorité de Certification.

create_ca.sh : Création de la CA.

create_device_cert.sh : Génération et signature d’un certificat device.

create_server_cert.sh : Génération et signature d’un certificat serveur.

revoke_cert.sh : Révocation d’un certificat compromis.
