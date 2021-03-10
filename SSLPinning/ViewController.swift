//
//  ViewController.swift
//  SSLPinning
//
//  Created by Milan Panchal on 09/03/21.
//

import UIKit

class ViewController: UIViewController {
    
    private let serverURL = "https://github.com"
    var activityView: UIActivityIndicatorView?

    // MARK:- View controller life cycle methods

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }

    // MARK:- IBAction methods
    @IBAction func didTapOnSSLPinningPublicKey(sender: UIButton) {
        sslPinningUsingPublicKeys(urlString: serverURL)
    }

    @IBAction func didTapOnSSLPinningCertificate(sender: UIButton) {
        sslPinningUsingCertificate(urlString: serverURL)
    }

    @IBAction func didTapOnSSLPinningUsingTrustKit(sender: UIButton) {
        sslPinningUsingTrustKit(urlString: serverURL)
    }

    // MARK:- User defined methods
    private func sslPinningUsingCertificate(urlString: String) {

        guard let url = URL(string: urlString) else { return }
        
        showActivityIndicator()
        NetworkManager.shared.callAPI(withURL: url, isCertificatePinning: true) { (message) in
            
            self.hideActivityIndicator()
            self.displayAlert(for: message)
        }
    }
    
    private func sslPinningUsingPublicKeys(urlString: String) {

        guard let url = URL(string: urlString) else { return }
        
        showActivityIndicator()
        NetworkManager.shared.callAPI(withURL: url, isCertificatePinning: false) { (message) in
            
            self.hideActivityIndicator()
            self.displayAlert(for: message)
        }

    }
    
    private func sslPinningUsingTrustKit(urlString: String) {

        guard let url = URL(string: urlString) else { return }

        showActivityIndicator()
        TrustKitNetworkManager.shared.callAPI(withURL: url) { (message) in
            
            self.hideActivityIndicator()
            self.displayAlert(for: message)
        }

    }
    
    private func showActivityIndicator() {
        view.isUserInteractionEnabled = false
        
        activityView = UIActivityIndicatorView(style: UIActivityIndicatorView.Style.large)
        activityView?.color = .darkGray
        activityView?.center = self.view.center
        self.view.addSubview(activityView!)
        activityView?.startAnimating()

    }
    
    private func hideActivityIndicator() {
        view.isUserInteractionEnabled = true
        activityView?.stopAnimating()
    }
    
    private func displayAlert(for message: String) {
        let alert = UIAlertController(
            title: "SSLPinning",
            message: message,
            preferredStyle: .alert
        )
        
        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        self.present(alert, animated: true, completion: nil)
    }
    
}
